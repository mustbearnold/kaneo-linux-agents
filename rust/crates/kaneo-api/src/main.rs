//! Rust runtime for the parts of Kaneo that are on the hot path for a local
//! installation: authenticated board reads, task mutations, and autonomous
//! agent execution.
//!
//! The router deliberately has a compatibility fallback. During the
//! migration, routes that have not moved yet are forwarded to the legacy
//! TypeScript API. This lets the Rust process become the single local API
//! origin without pretending that the remaining integration surface has
//! already been ported.

use axum::body::{Body, to_bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, patch, post, put};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use kaneo_core::{AgentRun, AgentSpec, RunManager, RunStatus, RunnerConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_postgres::{Client, NoTls, Row};
use uuid::Uuid;

const DEFAULT_BIND: &str = "127.0.0.1:1337";
const DEFAULT_MAX_BODY_BYTES: usize = 20 * 1024 * 1024;

#[derive(Debug, Clone)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Unauthorized")
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "message": self.message }))).into_response()
    }
}

fn database_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Rust database runtime error: {error}"),
    )
}

#[derive(Clone)]
struct Database {
    client: Arc<Client>,
}

impl Database {
    async fn connect(url: &str) -> Result<Self, ApiError> {
        let (client, connection) = tokio_postgres::connect(url, NoTls)
            .await
            .map_err(database_error)?;

        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("[kaneo-rust-api] PostgreSQL connection closed: {error}");
            }
        });

        Ok(Self {
            client: Arc::new(client),
        })
    }
}

#[derive(Clone)]
struct AppState {
    database: Database,
    runner: RunManager,
    http: reqwest::Client,
    legacy_api_url: Option<String>,
    events: broadcast::Sender<SocketEvent>,
}

#[derive(Clone, Debug)]
struct AuthContext {
    user_id: String,
    role: Option<String>,
    session_token: Option<String>,
    credential: String,
}

impl AuthContext {
    fn is_admin(&self) -> bool {
        self.role.as_deref() == Some("admin")
    }
}

#[derive(Debug, Deserialize, Default)]
struct ProjectQuery {
    #[serde(rename = "workspaceId")]
    workspace_id: Option<String>,
    #[serde(rename = "includeArchived")]
    include_archived: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct OrganizationQuery {
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    organization_slug: Option<String>,
    #[serde(rename = "membersLimit")]
    members_limit: Option<usize>,
    limit: Option<usize>,
    offset: Option<usize>,
    #[serde(rename = "sortBy")]
    sort_by: Option<String>,
    #[serde(rename = "sortDirection")]
    sort_direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct PermissionInput {
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    permission: Option<HashMap<String, Vec<String>>>,
    permissions: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Deserialize, Default)]
struct BoardQuery {
    status: Option<String>,
    priority: Option<String>,
    #[serde(rename = "assigneeId")]
    assignee_id: Option<String>,
    page: Option<usize>,
    limit: Option<usize>,
    #[serde(rename = "sortBy")]
    _sort_by: Option<String>,
    #[serde(rename = "sortOrder")]
    sort_order: Option<String>,
    #[serde(rename = "dueBefore")]
    due_before: Option<String>,
    #[serde(rename = "dueAfter")]
    due_after: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTaskInput {
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    start_date: Option<String>,
    #[serde(default)]
    due_date: Option<String>,
    #[serde(default = "default_priority")]
    priority: String,
    #[serde(default = "default_status")]
    status: String,
    #[serde(default)]
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTaskInput {
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    start_date: Option<String>,
    #[serde(default)]
    due_date: Option<String>,
    #[serde(default = "default_priority")]
    priority: String,
    status: String,
    project_id: String,
    #[serde(default)]
    position: i32,
    #[serde(default)]
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StatusInput {
    status: String,
}

#[derive(Debug, Deserialize)]
struct PriorityInput {
    priority: String,
}

#[derive(Debug, Deserialize)]
struct TitleInput {
    title: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DueDateInput {
    due_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartAgentInput {
    project_id: String,
    prompt: String,
    cwd: Option<String>,
    model: Option<String>,
    network_access: Option<bool>,
    max_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Label {
    id: String,
    name: String,
    color: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LabelRecord {
    id: String,
    name: String,
    color: String,
    created_at: String,
    updated_at: String,
    task_id: Option<String>,
    workspace_id: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ExternalLink {
    id: String,
    task_id: String,
    integration_id: String,
    resource_type: String,
    external_id: String,
    url: String,
    title: Option<String>,
    metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalLinkRecord {
    id: String,
    task_id: String,
    integration_id: String,
    resource_type: String,
    external_id: String,
    url: String,
    title: Option<String>,
    metadata: Option<Value>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ApiTask {
    id: String,
    title: String,
    number: Option<i32>,
    description: Option<String>,
    status: String,
    priority: Option<String>,
    start_date: Option<String>,
    due_date: Option<String>,
    position: Option<i32>,
    created_at: String,
    user_id: Option<String>,
    assignee_name: Option<String>,
    assignee_id: Option<String>,
    project_id: String,
    labels: Vec<Label>,
    external_links: Vec<ExternalLink>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Column {
    id: String,
    slug: String,
    name: String,
    icon: Option<String>,
    color: Option<String>,
    is_final: bool,
    position: i32,
    tasks: Vec<ApiTask>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BoardProject {
    id: String,
    name: String,
    slug: String,
    icon: Option<String>,
    description: Option<String>,
    is_public: bool,
    workspace_id: String,
    columns: Vec<Column>,
    archived_tasks: Vec<ApiTask>,
    planned_tasks: Vec<ApiTask>,
}

#[derive(Debug, Serialize)]
struct Pagination {
    total: usize,
    page: usize,
    #[serde(rename = "pageSize")]
    page_size: usize,
    #[serde(rename = "totalPages")]
    total_pages: usize,
}

#[derive(Debug, Serialize)]
struct BoardResponse {
    data: BoardProject,
    pagination: Pagination,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentEventResponse {
    at: String,
    #[serde(rename = "type")]
    event_type: String,
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentRunResponse {
    id: String,
    workspace_id: String,
    project_id: String,
    prompt: String,
    cwd: String,
    model: Option<String>,
    network_access: bool,
    status: RunStatus,
    created_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    exit_code: Option<i32>,
    error: Option<String>,
    events: Vec<AgentEventResponse>,
}

#[derive(Debug, Deserialize, Default)]
struct SocketQuery {
    #[serde(rename = "windowId")]
    window_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SocketEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_task_id: Option<String>,
    #[serde(skip)]
    initiator_id: Option<String>,
}

fn default_status() -> String {
    "to-do".to_string()
}

fn default_priority() -> String {
    "no-priority".to_string()
}

fn env_true(name: &str) -> bool {
    env::var(name).is_ok_and(|value| value == "true")
}

fn env_present(name: &str) -> bool {
    env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

fn socket_initiator(auth: &AuthContext, headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-kaneo-window-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(|window_id| format!("{}:{window_id}", auth.user_id))
}

fn publish_task_event(
    state: &AppState,
    event_type: &str,
    project_id: impl Into<String>,
    task_id: impl Into<String>,
    auth: &AuthContext,
    headers: &HeaderMap,
) {
    let _ = state.events.send(SocketEvent {
        event_type: event_type.to_string(),
        project_id: Some(project_id.into()),
        task_id: Some(task_id.into()),
        source_task_id: None,
        target_task_id: None,
        initiator_id: socket_initiator(auth, headers),
    });
}

fn publish_task_move(
    state: &AppState,
    project_id: impl Into<String>,
    task_id: impl Into<String>,
    auth: &AuthContext,
    headers: &HeaderMap,
) {
    let _ = state.events.send(SocketEvent {
        event_type: "TASK_MOVED".to_string(),
        project_id: Some(project_id.into()),
        task_id: Some(task_id.into()),
        source_task_id: None,
        target_task_id: None,
        initiator_id: socket_initiator(auth, headers),
    });
}

fn row_string(row: &Row, name: &str) -> Result<String, ApiError> {
    row.try_get(name).map_err(database_error)
}

fn row_optional_string(row: &Row, name: &str) -> Result<Option<String>, ApiError> {
    row.try_get(name).map_err(database_error)
}

fn row_optional_i32(row: &Row, name: &str) -> Result<Option<i32>, ApiError> {
    row.try_get(name).map_err(database_error)
}

fn task_from_row(row: &Row) -> Result<ApiTask, ApiError> {
    Ok(ApiTask {
        id: row_string(row, "id")?,
        title: row_string(row, "title")?,
        number: row_optional_i32(row, "number")?,
        description: row_optional_string(row, "description")?,
        status: row_string(row, "status")?,
        priority: row_optional_string(row, "priority")?,
        start_date: row_optional_string(row, "start_date")?,
        due_date: row_optional_string(row, "due_date")?,
        position: row_optional_i32(row, "position")?,
        created_at: row_string(row, "created_at")?,
        user_id: row_optional_string(row, "user_id")?,
        assignee_name: row_optional_string(row, "assignee_name")?,
        assignee_id: row_optional_string(row, "assignee_id")?,
        project_id: row_string(row, "project_id")?,
        labels: Vec::new(),
        external_links: Vec::new(),
    })
}

fn task_select_sql() -> &'static str {
    r#"
        SELECT
          t.id,
          t.title,
          t.number,
          t.description,
          t.status,
          t.priority,
          to_char(t.start_date AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS start_date,
          to_char(t.due_date AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS due_date,
          t.position,
          to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
          t.assignee_id AS user_id,
          u.name AS assignee_name,
          u.id AS assignee_id,
          t.project_id
        FROM task t
        LEFT JOIN "user" u ON u.id = t.assignee_id
    "#
}

async fn task_by_id(database: &Database, task_id: &str) -> Result<ApiTask, ApiError> {
    let sql = format!("{} WHERE t.id = $1 LIMIT 1", task_select_sql());
    let row = database
        .client
        .query_opt(&sql, &[&task_id])
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Task not found"))?;
    task_from_row(&row)
}

async fn load_task_extras(
    database: &Database,
    project_id: &str,
) -> Result<
    (
        HashMap<String, Vec<Label>>,
        HashMap<String, Vec<ExternalLink>>,
    ),
    ApiError,
> {
    let label_rows = database
        .client
        .query(
            r#"
              SELECT l.id, l.name, l.color, l.task_id
              FROM label l
              INNER JOIN task t ON t.id = l.task_id
              WHERE t.project_id = $1
            "#,
            &[&project_id],
        )
        .await
        .map_err(database_error)?;
    let mut labels = HashMap::new();
    for row in label_rows {
        let task_id: String = row.try_get("task_id").map_err(database_error)?;
        labels.entry(task_id).or_insert_with(Vec::new).push(Label {
            id: row_string(&row, "id")?,
            name: row_string(&row, "name")?,
            color: row_string(&row, "color")?,
        });
    }

    let link_rows = database
        .client
        .query(
            r#"
              SELECT e.id, e.task_id, e.integration_id, e.resource_type,
                     e.external_id, e.url, e.title, e.metadata
              FROM external_link e
              INNER JOIN task t ON t.id = e.task_id
              WHERE t.project_id = $1
            "#,
            &[&project_id],
        )
        .await
        .map_err(database_error)?;
    let mut links = HashMap::new();
    for row in link_rows {
        let task_id: String = row.try_get("task_id").map_err(database_error)?;
        let metadata =
            row_optional_string(&row, "metadata")?.and_then(|raw| serde_json::from_str(&raw).ok());
        links
            .entry(task_id)
            .or_insert_with(Vec::new)
            .push(ExternalLink {
                id: row_string(&row, "id")?,
                task_id: row_string(&row, "task_id")?,
                integration_id: row_string(&row, "integration_id")?,
                resource_type: row_string(&row, "resource_type")?,
                external_id: row_string(&row, "external_id")?,
                url: row_string(&row, "url")?,
                title: row_optional_string(&row, "title")?,
                metadata,
            });
    }

    Ok((labels, links))
}

fn attach_task_extras(
    tasks: &mut [ApiTask],
    labels: &HashMap<String, Vec<Label>>,
    links: &HashMap<String, Vec<ExternalLink>>,
) {
    for task in tasks {
        task.labels = labels.get(&task.id).cloned().unwrap_or_default();
        task.external_links = links.get(&task.id).cloned().unwrap_or_default();
    }
}

async fn project_workspace(database: &Database, project_id: &str) -> Result<String, ApiError> {
    database
        .client
        .query_opt(
            "SELECT workspace_id FROM project WHERE id = $1 LIMIT 1",
            &[&project_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_string(&row, "workspace_id"))
        .transpose()?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Project not found"))
}

async fn task_workspace(database: &Database, task_id: &str) -> Result<String, ApiError> {
    database
        .client
        .query_opt(
            r#"
              SELECT p.workspace_id
              FROM task t
              INNER JOIN project p ON p.id = t.project_id
              WHERE t.id = $1
              LIMIT 1
            "#,
            &[&task_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_string(&row, "workspace_id"))
        .transpose()?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Task not found"))
}

async fn column_for_status(
    database: &Database,
    project_id: &str,
    status: &str,
) -> Result<Option<String>, ApiError> {
    if matches!(status, "planned" | "archived") {
        return Ok(None);
    }
    database
        .client
        .query_opt(
            "SELECT id FROM \"column\" WHERE project_id = $1 AND slug = $2 LIMIT 1",
            &[&project_id, &status],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_string(&row, "id"))
        .transpose()?
        .map(Some)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("Invalid task status for this project: {status}"),
            )
        })
}

fn validate_priority(priority: &str) -> Result<(), ApiError> {
    if matches!(
        priority,
        "no-priority" | "low" | "medium" | "high" | "urgent"
    ) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid priority: {priority}"),
        ))
    }
}

async fn require_workspace(
    state: &AppState,
    auth: &AuthContext,
    workspace_id: &str,
) -> Result<(), ApiError> {
    if auth.is_admin() {
        return Ok(());
    }

    let member = state
        .database
        .client
        .query_opt(
            "SELECT 1 FROM workspace_member WHERE workspace_id = $1 AND user_id = $2 LIMIT 1",
            &[&workspace_id, &auth.user_id],
        )
        .await
        .map_err(database_error)?;
    if member.is_none() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "You don't have access to this workspace",
        ));
    }
    Ok(())
}

fn cookie_credential(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        match name {
            "better-auth.session_token" | "__Secure-better-auth.session_token" => {
                Some(value.to_string())
            }
            _ => None,
        }
    })
}

fn bearer_credential(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty())
        .then(|| token.trim().to_string())
}

fn api_key_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<AuthContext, ApiError> {
    let api_key_header = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let bearer = bearer_credential(headers);
    if let Some(api_key) = api_key_header.or_else(|| bearer.clone()) {
        let hashed = api_key_hash(&api_key);
        if let Some(row) = state
            .database
            .client
            .query_opt(
                r#"
                  SELECT id, COALESCE(reference_id, user_id) AS user_id
                  FROM apikey
                  WHERE key = $1
                    AND enabled = TRUE
                    AND (expires_at IS NULL OR expires_at > NOW())
                  LIMIT 1
                "#,
                &[&hashed],
            )
            .await
            .map_err(database_error)?
        {
            let user_id: String = row.try_get("user_id").map_err(database_error)?;
            let role = state
                .database
                .client
                .query_opt("SELECT role FROM \"user\" WHERE id = $1", &[&user_id])
                .await
                .map_err(database_error)?
                .and_then(|row| row.try_get("role").ok());
            return Ok(AuthContext {
                user_id,
                role,
                session_token: None,
                credential: api_key,
            });
        }
    }

    let raw_session = bearer.or_else(|| cookie_credential(headers));
    let Some(raw_session) = raw_session else {
        return Err(ApiError::unauthorized());
    };
    let session_token = raw_session
        .split(|character| character == '|' || character == '.')
        .next()
        .unwrap_or(&raw_session);
    let Some(row) = state
        .database
        .client
        .query_opt(
            r#"
              SELECT s.id, s.token, s.user_id, s.active_organization_id, u.role
              FROM session s
              INNER JOIN "user" u ON u.id = s.user_id
              WHERE s.token = $1 AND s.expires_at > NOW()
              LIMIT 1
            "#,
            &[&session_token],
        )
        .await
        .map_err(database_error)?
    else {
        return Err(ApiError::unauthorized());
    };

    Ok(AuthContext {
        user_id: row.try_get("user_id").map_err(database_error)?,
        role: row.try_get("role").map_err(database_error)?,
        session_token: Some(row.try_get("token").map_err(database_error)?),
        credential: raw_session,
    })
}

async fn auth_for_project(
    state: &AppState,
    headers: &HeaderMap,
    project_id: &str,
) -> Result<(AuthContext, String), ApiError> {
    let auth = authenticate(state, headers).await?;
    let workspace_id = project_workspace(&state.database, project_id).await?;
    require_workspace(state, &auth, &workspace_id).await?;
    Ok((auth, workspace_id))
}

async fn auth_for_task(
    state: &AppState,
    headers: &HeaderMap,
    task_id: &str,
) -> Result<(AuthContext, String), ApiError> {
    let auth = authenticate(state, headers).await?;
    let workspace_id = task_workspace(&state.database, task_id).await?;
    require_workspace(state, &auth, &workspace_id).await?;
    Ok((auth, workspace_id))
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "runtime": "rust" }))
}

async fn config() -> Json<Value> {
    let github_sso = (env_present("GITHUB_OAUTH_CLIENT_ID")
        && env_present("GITHUB_OAUTH_CLIENT_SECRET"))
        || (env_present("GITHUB_CLIENT_ID") && env_present("GITHUB_CLIENT_SECRET"));
    Json(json!({
        "disableRegistration": env_true("DISABLE_REGISTRATION"),
        "disablePasswordRegistration": env_true("DISABLE_PASSWORD_REGISTRATION"),
        "disableEmailOtpSignIn": env_true("DISABLE_EMAIL_OTP_SIGN_IN"),
        "isDemoMode": env_true("DEMO_MODE"),
        "hasSmtp": env_present("SMTP_HOST")
            && env_present("SMTP_PORT")
            && env_present("SMTP_SECURE")
            && env_present("SMTP_USER")
            && env_present("SMTP_PASSWORD"),
        "hasGithubSignIn": github_sso,
        "hasGoogleSignIn": env_present("GOOGLE_CLIENT_ID") && env_present("GOOGLE_CLIENT_SECRET"),
        "hasDiscordSignIn": env_present("DISCORD_CLIENT_ID") && env_present("DISCORD_CLIENT_SECRET"),
        "hasCustomOAuth": env_present("CUSTOM_OAUTH_CLIENT_ID")
            && env_present("CUSTOM_OAUTH_CLIENT_SECRET"),
        "hasGuestAccess": !env_true("DISABLE_GUEST_ACCESS"),
        "disableLoginForm": env_true("DISABLE_LOGIN_FORM"),
        "customOAuthAutoLogin": env_true("CUSTOM_OAUTH_AUTO_LOGIN"),
        "customOAuthLogoutUrl": env::var("CUSTOM_OAUTH_LOGOUT_URL").ok().filter(|value| !value.is_empty()),
        "billingEnabled": env_true("KANEO_CLOUD")
            && env_present("CREEM_API_KEY")
            && env_present("CREEM_WEBHOOK_SECRET"),
    }))
}

async fn rust_status(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "runtime": "rust",
        "database": "postgres",
        "legacyProxy": state.legacy_api_url.is_some(),
        "agentRunner": "kaneo-core",
        "websocket": true,
    }))
}

async fn list_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ProjectQuery>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let workspace_id = query
        .workspace_id
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "workspaceId is required"))?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let include_archived = query.include_archived.as_deref() == Some("true");

    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT
                p.id, p.workspace_id, p.slug, p.icon, p.name, p.description,
                to_char(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                COALESCE(p.is_public, FALSE) AS is_public,
                COUNT(t.id)::int AS total_tasks,
                COUNT(t.id) FILTER (WHERE t.status IN ('done', 'archived'))::int AS completed_tasks,
                to_char(MIN(t.due_date) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS due_date
              FROM project p
              LEFT JOIN task t ON t.project_id = p.id
              WHERE p.workspace_id = $1
                AND ($2 OR p.archived_at IS NULL)
              GROUP BY p.id
              ORDER BY p.created_at ASC
            "#,
            &[&workspace_id, &include_archived],
        )
        .await
        .map_err(database_error)?;

    let projects = rows
        .into_iter()
        .map(|row| {
            let total_tasks: i32 = row.try_get("total_tasks").map_err(database_error)?;
            let completed_tasks: i32 = row.try_get("completed_tasks").map_err(database_error)?;
            let completion_percentage = if total_tasks > 0 {
                ((completed_tasks as f64 / total_tasks as f64) * 100.0).round() as i32
            } else {
                0
            };
            Ok(json!({
                "id": row_string(&row, "id")?,
                "workspaceId": row_string(&row, "workspace_id")?,
                "slug": row_string(&row, "slug")?,
                "icon": row_optional_string(&row, "icon")?,
                "name": row_string(&row, "name")?,
                "description": row_optional_string(&row, "description")?,
                "createdAt": row_string(&row, "created_at")?,
                "isPublic": row.try_get::<_, bool>("is_public").map_err(database_error)?,
                "statistics": {
                    "completionPercentage": completion_percentage,
                    "totalTasks": total_tasks,
                    "dueDate": row_optional_string(&row, "due_date")?,
                },
                "archivedTasks": [],
                "plannedTasks": [],
                "columns": [],
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    Ok(Json(Value::Array(projects)))
}

async fn get_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ProjectQuery>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &id).await?;
    if let Some(requested_workspace) = query.workspace_id {
        if requested_workspace != workspace_id {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "Workspace mismatch"));
        }
    }
    let _ = auth;
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT p.id, p.workspace_id, p.slug, p.icon, p.name, p.description,
                     to_char(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     COALESCE(p.is_public, FALSE) AS is_public
              FROM project p
              WHERE p.id = $1 AND p.workspace_id = $2
              LIMIT 1
            "#,
            &[&id, &workspace_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Project not found"))?;
    let task_rows = state
        .database
        .client
        .query(
            &format!(
                "{} WHERE t.project_id = $1 ORDER BY t.position ASC",
                task_select_sql()
            ),
            &[&id],
        )
        .await
        .map_err(database_error)?;
    let mut tasks = task_rows
        .iter()
        .map(task_from_row)
        .collect::<Result<Vec<_>, ApiError>>()?;
    let (labels, links) = load_task_extras(&state.database, &id).await?;
    attach_task_extras(&mut tasks, &labels, &links);

    Ok(Json(json!({
        "id": row_string(&row, "id")?,
        "workspaceId": row_string(&row, "workspace_id")?,
        "slug": row_string(&row, "slug")?,
        "icon": row_optional_string(&row, "icon")?,
        "name": row_string(&row, "name")?,
        "description": row_optional_string(&row, "description")?,
        "createdAt": row_string(&row, "created_at")?,
        "isPublic": row.try_get::<_, bool>("is_public").map_err(database_error)?,
        "tasks": tasks,
    })))
}

async fn list_columns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _ = auth_for_project(&state, &headers, &project_id).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT id, project_id, name, slug, position, icon, color, is_final,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM "column"
              WHERE project_id = $1
              ORDER BY position ASC
            "#,
            &[&project_id],
        )
        .await
        .map_err(database_error)?;
    let columns = rows
        .into_iter()
        .map(|row| {
            Ok(json!({
                "id": row_string(&row, "id")?,
                "projectId": row_string(&row, "project_id")?,
                "name": row_string(&row, "name")?,
                "slug": row_string(&row, "slug")?,
                "position": row.try_get::<_, i32>("position").map_err(database_error)?,
                "icon": row_optional_string(&row, "icon")?,
                "color": row_optional_string(&row, "color")?,
                "isFinal": row.try_get::<_, bool>("is_final").map_err(database_error)?,
                "createdAt": row_string(&row, "created_at")?,
                "updatedAt": row_string(&row, "updated_at")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(Value::Array(columns)))
}

async fn list_task_labels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Result<Json<Vec<LabelRecord>>, ApiError> {
    let _ = auth_for_task(&state, &headers, &task_id).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT id, name, color,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
                     task_id, workspace_id
              FROM label
              WHERE task_id = $1
              ORDER BY name ASC
            "#,
            &[&task_id],
        )
        .await
        .map_err(database_error)?;
    rows.into_iter()
        .map(|row| {
            Ok(LabelRecord {
                id: row_string(&row, "id")?,
                name: row_string(&row, "name")?,
                color: row_string(&row, "color")?,
                created_at: row_string(&row, "created_at")?,
                updated_at: row_string(&row, "updated_at")?,
                task_id: row_optional_string(&row, "task_id")?,
                workspace_id: row_optional_string(&row, "workspace_id")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
        .map(Json)
}

async fn list_workspace_labels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<Vec<LabelRecord>>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT id, name, color,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
                     task_id, workspace_id
              FROM label
              WHERE workspace_id = $1
              ORDER BY name ASC
            "#,
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    rows.into_iter()
        .map(|row| {
            Ok(LabelRecord {
                id: row_string(&row, "id")?,
                name: row_string(&row, "name")?,
                color: row_string(&row, "color")?,
                created_at: row_string(&row, "created_at")?,
                updated_at: row_string(&row, "updated_at")?,
                task_id: row_optional_string(&row, "task_id")?,
                workspace_id: row_optional_string(&row, "workspace_id")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
        .map(Json)
}

async fn list_external_links(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Result<Json<Vec<ExternalLinkRecord>>, ApiError> {
    let _ = auth_for_task(&state, &headers, &task_id).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT id, task_id, integration_id, resource_type, external_id,
                     url, title, metadata,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM external_link
              WHERE task_id = $1
              ORDER BY created_at ASC
            "#,
            &[&task_id],
        )
        .await
        .map_err(database_error)?;
    rows.into_iter()
        .map(|row| {
            let metadata = row_optional_string(&row, "metadata")?
                .and_then(|raw| serde_json::from_str(&raw).ok());
            Ok(ExternalLinkRecord {
                id: row_string(&row, "id")?,
                task_id: row_string(&row, "task_id")?,
                integration_id: row_string(&row, "integration_id")?,
                resource_type: row_string(&row, "resource_type")?,
                external_id: row_string(&row, "external_id")?,
                url: row_string(&row, "url")?,
                title: row_optional_string(&row, "title")?,
                metadata,
                created_at: row_string(&row, "created_at")?,
                updated_at: row_string(&row, "updated_at")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
        .map(Json)
}

async fn load_board(
    state: &AppState,
    project_id: &str,
    query: &BoardQuery,
) -> Result<BoardResponse, ApiError> {
    let project_row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT p.id, p.name, p.slug, p.icon, p.description,
                     COALESCE(p.is_public, FALSE) AS is_public, p.workspace_id
              FROM project p
              WHERE p.id = $1
              LIMIT 1
            "#,
            &[&project_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Project not found"))?;
    let task_rows = state
        .database
        .client
        .query(
            &format!(
                "{} WHERE t.project_id = $1 ORDER BY t.position ASC",
                task_select_sql()
            ),
            &[&project_id],
        )
        .await
        .map_err(database_error)?;
    let mut tasks = task_rows
        .iter()
        .map(task_from_row)
        .collect::<Result<Vec<_>, ApiError>>()?;

    tasks.retain(|task| {
        query
            .status
            .as_deref()
            .is_none_or(|value| task.status == value)
            && query
                .priority
                .as_deref()
                .is_none_or(|value| task.priority.as_deref() == Some(value))
            && query
                .assignee_id
                .as_deref()
                .is_none_or(|value| task.user_id.as_deref() == Some(value))
            && query
                .due_before
                .as_deref()
                .is_none_or(|value| task.due_date.as_deref().is_some_and(|date| date <= value))
            && query
                .due_after
                .as_deref()
                .is_none_or(|value| task.due_date.as_deref().is_some_and(|date| date >= value))
    });
    if matches!(query.sort_order.as_deref(), Some("desc")) {
        tasks.reverse();
    }
    let total = tasks.len();
    let use_pagination = query.page.is_some() || query.limit.is_some();
    let page = query.page.filter(|page| *page > 0).unwrap_or(1);
    let page_size = query
        .limit
        .filter(|limit| *limit > 0)
        .unwrap_or(50)
        .min(100);
    if use_pagination {
        let start = (page - 1).saturating_mul(page_size).min(tasks.len());
        let end = (start + page_size).min(tasks.len());
        tasks = tasks[start..end].to_vec();
    }
    let (labels, links) = load_task_extras(&state.database, project_id).await?;
    attach_task_extras(&mut tasks, &labels, &links);

    let column_rows = state
        .database
        .client
        .query(
            "SELECT id, name, slug, position, icon, color, is_final FROM \"column\" WHERE project_id = $1 ORDER BY position ASC",
            &[&project_id],
        )
        .await
        .map_err(database_error)?;
    let mut columns = Vec::with_capacity(column_rows.len());
    for row in column_rows {
        let slug = row_string(&row, "slug")?;
        columns.push(Column {
            id: slug.clone(),
            slug,
            name: row_string(&row, "name")?,
            icon: row_optional_string(&row, "icon")?,
            color: row_optional_string(&row, "color")?,
            is_final: row.try_get("is_final").map_err(database_error)?,
            position: row.try_get("position").map_err(database_error)?,
            tasks: Vec::new(),
        });
    }
    for column in &mut columns {
        column.tasks = tasks
            .iter()
            .filter(|task| task.status == column.slug)
            .cloned()
            .collect();
    }
    let archived_tasks = tasks
        .iter()
        .filter(|task| task.status == "archived")
        .cloned()
        .collect();
    let planned_tasks = tasks
        .iter()
        .filter(|task| task.status == "planned")
        .cloned()
        .collect();
    let page_count = if total == 0 {
        1
    } else {
        total.div_ceil(page_size)
    };

    Ok(BoardResponse {
        data: BoardProject {
            id: row_string(&project_row, "id")?,
            name: row_string(&project_row, "name")?,
            slug: row_string(&project_row, "slug")?,
            icon: row_optional_string(&project_row, "icon")?,
            description: row_optional_string(&project_row, "description")?,
            is_public: project_row.try_get("is_public").map_err(database_error)?,
            workspace_id: row_string(&project_row, "workspace_id")?,
            columns,
            archived_tasks: archived_tasks,
            planned_tasks,
        },
        pagination: Pagination {
            total,
            page,
            page_size: if use_pagination { page_size } else { total },
            total_pages: if use_pagination { page_count } else { 1 },
        },
    })
}

async fn list_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Query(query): Query<BoardQuery>,
) -> Result<Json<BoardResponse>, ApiError> {
    let _ = auth_for_project(&state, &headers, &project_id).await?;
    Ok(Json(load_board(&state, &project_id, &query).await?))
}

async fn get_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiTask>, ApiError> {
    let _ = auth_for_task(&state, &headers, &id).await?;
    Ok(Json(task_by_id(&state.database, &id).await?))
}

async fn update_task_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<StatusInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, _) = auth_for_task(&state, &headers, &id).await?;
    let project_id: String = state
        .database
        .client
        .query_one("SELECT project_id FROM task WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?
        .try_get("project_id")
        .map_err(database_error)?;
    let column_id = column_for_status(&state.database, &project_id, &input.status).await?;
    state
        .database
        .client
        .execute(
            "UPDATE task SET status = $1, column_id = $2, updated_at = NOW() WHERE id = $3",
            &[&input.status, &column_id, &id],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &id).await?;
    publish_task_event(
        &state,
        "TASK_UPDATED",
        task.project_id.clone(),
        id,
        &auth,
        &headers,
    );
    Ok(Json(task))
}

async fn update_task_title(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<TitleInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, _) = auth_for_task(&state, &headers, &id).await?;
    state
        .database
        .client
        .execute(
            "UPDATE task SET title = $1, updated_at = NOW() WHERE id = $2",
            &[&input.title, &id],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &id).await?;
    publish_task_event(
        &state,
        "TASK_UPDATED",
        task.project_id.clone(),
        id,
        &auth,
        &headers,
    );
    Ok(Json(task))
}

async fn update_task_priority(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<PriorityInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, _) = auth_for_task(&state, &headers, &id).await?;
    validate_priority(&input.priority)?;
    state
        .database
        .client
        .execute(
            "UPDATE task SET priority = $1, updated_at = NOW() WHERE id = $2",
            &[&input.priority, &id],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &id).await?;
    publish_task_event(
        &state,
        "TASK_UPDATED",
        task.project_id.clone(),
        id,
        &auth,
        &headers,
    );
    Ok(Json(task))
}

async fn update_task_due_date(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<DueDateInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, _) = auth_for_task(&state, &headers, &id).await?;
    state
        .database
        .client
        .execute(
            "UPDATE task SET due_date = $1::text::timestamptz AT TIME ZONE 'UTC', updated_at = NOW() WHERE id = $2",
            &[&input.due_date, &id],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &id).await?;
    publish_task_event(
        &state,
        "TASK_UPDATED",
        task.project_id.clone(),
        id,
        &auth,
        &headers,
    );
    Ok(Json(task))
}

async fn create_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<CreateTaskInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, _) = auth_for_project(&state, &headers, &project_id).await?;
    validate_priority(&input.priority)?;
    let column_id = column_for_status(&state.database, &project_id, &input.status).await?;
    let number: i32 = state
        .database
        .client
        .query_one(
            "UPDATE project SET last_task_number = last_task_number + 1 WHERE id = $1 RETURNING last_task_number",
            &[&project_id],
        )
        .await
        .map_err(database_error)?
        .try_get("last_task_number")
        .map_err(database_error)?;
    let position: i32 = state
        .database
        .client
        .query_one(
            "SELECT COALESCE(MAX(position), 0) + 1 AS position FROM task WHERE project_id = $1 AND status = $2",
            &[&project_id, &input.status],
        )
        .await
        .map_err(database_error)?
        .try_get("position")
        .map_err(database_error)?;
    let id = Uuid::new_v4().to_string();
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO task
                (id, project_id, position, number, assignee_id, title, description,
                 status, column_id, priority, start_date, due_date, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                      $11::text::timestamptz AT TIME ZONE 'UTC',
                      $12::text::timestamptz AT TIME ZONE 'UTC', NOW(), NOW())
            "#,
            &[
                &id,
                &project_id,
                &position,
                &number,
                &input.user_id,
                &input.title,
                &input.description,
                &input.status,
                &column_id,
                &input.priority,
                &input.start_date,
                &input.due_date,
            ],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &id).await?;
    publish_task_event(
        &state,
        "TASK_CREATED",
        task.project_id.clone(),
        id,
        &auth,
        &headers,
    );
    Ok(Json(task))
}

async fn update_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateTaskInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, source_workspace) = auth_for_task(&state, &headers, &id).await?;
    let (_, destination_workspace) = auth_for_project(&state, &headers, &input.project_id).await?;
    if destination_workspace != source_workspace {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "A task cannot be moved across workspaces by this endpoint",
        ));
    }
    validate_priority(&input.priority)?;
    let source_task = task_by_id(&state.database, &id).await?;
    let source_project_id = source_task.project_id.clone();
    let column_id = column_for_status(&state.database, &input.project_id, &input.status).await?;
    state
        .database
        .client
        .execute(
            r#"
              UPDATE task
              SET project_id = $1, position = $2, assignee_id = $3, title = $4,
                  description = $5, status = $6, column_id = $7, priority = $8,
                  start_date = $9::text::timestamptz AT TIME ZONE 'UTC',
                  due_date = $10::text::timestamptz AT TIME ZONE 'UTC',
                  updated_at = NOW()
              WHERE id = $11
            "#,
            &[
                &input.project_id,
                &input.position,
                &input.user_id,
                &input.title,
                &input.description,
                &input.status,
                &column_id,
                &input.priority,
                &input.start_date,
                &input.due_date,
                &id,
            ],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &id).await?;
    if source_project_id == task.project_id {
        publish_task_event(
            &state,
            "TASK_UPDATED",
            task.project_id.clone(),
            id,
            &auth,
            &headers,
        );
    } else {
        publish_task_move(&state, source_project_id, id.clone(), &auth, &headers);
        publish_task_move(&state, task.project_id.clone(), id, &auth, &headers);
    }
    Ok(Json(task))
}

async fn delete_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, _) = auth_for_task(&state, &headers, &id).await?;
    let task = task_by_id(&state.database, &id).await?;
    state
        .database
        .client
        .execute("DELETE FROM task WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?;
    publish_task_event(
        &state,
        "TASK_DELETED",
        task.project_id.clone(),
        id,
        &auth,
        &headers,
    );
    Ok(Json(task))
}

async fn session_json(state: &AppState, auth: &AuthContext) -> Result<Value, ApiError> {
    let Some(session_token) = auth.session_token.as_deref() else {
        return Ok(Value::Null);
    };
    let user = state
        .database
        .client
        .query_one(
            r#"
              SELECT id, name, email, email_verified, image, locale,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
                     COALESCE(is_anonymous, FALSE) AS is_anonymous, role
              FROM "user" WHERE id = $1
            "#,
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;
    let session = state
        .database
        .client
        .query_one(
            r#"
              SELECT id, token,
                     to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
                     active_organization_id
              FROM session WHERE token = $1
            "#,
            &[&session_token],
        )
        .await
        .map_err(database_error)?;
    Ok(json!({
        "session": {
            "id": row_string(&session, "id")?,
            "token": row_string(&session, "token")?,
            "expiresAt": row_string(&session, "expires_at")?,
            "createdAt": row_string(&session, "created_at")?,
            "updatedAt": row_string(&session, "updated_at")?,
            "userId": auth.user_id,
            "activeOrganizationId": row_optional_string(&session, "active_organization_id")?,
        },
        "user": {
            "id": row_string(&user, "id")?,
            "name": row_string(&user, "name")?,
            "email": row_string(&user, "email")?,
            "emailVerified": user.try_get::<_, bool>("email_verified").map_err(database_error)?,
            "image": row_optional_string(&user, "image")?,
            "locale": row_optional_string(&user, "locale")?,
            "createdAt": row_string(&user, "created_at")?,
            "updatedAt": row_string(&user, "updated_at")?,
            "isAnonymous": user.try_get::<_, bool>("is_anonymous").map_err(database_error)?,
            "role": row_optional_string(&user, "role")?,
        }
    }))
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    match authenticate(&state, &headers).await {
        Ok(auth) => Ok(Json(session_json(&state, &auth).await?)),
        Err(error) if error.status == StatusCode::UNAUTHORIZED => Ok(Json(Value::Null)),
        Err(error) => Err(error),
    }
}

async fn list_organizations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT w.id, w.name, w.slug, w.logo, w.metadata, w.description,
                     to_char(w.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
              FROM workspace w
              INNER JOIN workspace_member m ON m.workspace_id = w.id
              WHERE m.user_id = $1
              ORDER BY w.created_at ASC
            "#,
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;
    let organizations = rows
        .into_iter()
        .map(|row| {
            let metadata = row_optional_string(&row, "metadata")
                .ok()
                .flatten()
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                .unwrap_or(Value::Null);
            Ok(json!({
                "id": row_string(&row, "id")?,
                "name": row_string(&row, "name")?,
                "slug": row_string(&row, "slug")?,
                "logo": row_optional_string(&row, "logo")?,
                "description": row_optional_string(&row, "description")?,
                "metadata": metadata,
                "createdAt": row_string(&row, "created_at")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(Value::Array(organizations)))
}

async fn active_organization_id(
    state: &AppState,
    auth: &AuthContext,
) -> Result<Option<String>, ApiError> {
    let Some(session_token) = auth.session_token.as_deref() else {
        return Ok(None);
    };
    state
        .database
        .client
        .query_opt(
            "SELECT active_organization_id FROM session WHERE token = $1 LIMIT 1",
            &[&session_token],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_optional_string(&row, "active_organization_id"))
        .transpose()
        .map(|value| value.flatten())
}

async fn resolve_organization_id(
    state: &AppState,
    auth: &AuthContext,
    organization_id: Option<&str>,
    organization_slug: Option<&str>,
) -> Result<String, ApiError> {
    if let Some(organization_id) = organization_id.filter(|value| !value.trim().is_empty()) {
        return Ok(organization_id.to_string());
    }

    if let Some(organization_slug) = organization_slug.filter(|value| !value.trim().is_empty()) {
        return state
            .database
            .client
            .query_opt(
                "SELECT id FROM workspace WHERE slug = $1 LIMIT 1",
                &[&organization_slug],
            )
            .await
            .map_err(database_error)?
            .map(|row| row_string(&row, "id"))
            .transpose()?
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Organization not found"));
    }

    active_organization_id(state, auth)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "No active organization"))
}

fn organization_member_json(row: &Row) -> Result<Value, ApiError> {
    Ok(json!({
        "id": row_string(row, "member_id")?,
        "organizationId": row_string(row, "organization_id")?,
        "userId": row_string(row, "user_id")?,
        "role": row_string(row, "role")?,
        "createdAt": row_string(row, "member_created_at")?,
        "user": {
            "id": row_string(row, "user_id")?,
            "name": row_string(row, "user_name")?,
            "email": row_string(row, "user_email")?,
            "image": row_optional_string(row, "user_image")?,
        },
    }))
}

async fn list_organization_members(
    state: &AppState,
    organization_id: &str,
    limit: usize,
    offset: usize,
    sort_by: Option<&str>,
    sort_direction: Option<&str>,
) -> Result<(Vec<Value>, i64), ApiError> {
    let sort_column = match sort_by {
        Some("role") => "m.role",
        Some("userId") => "m.user_id",
        Some("createdAt") | Some("joinedAt") => "m.joined_at",
        _ => "m.joined_at",
    };
    let sort_direction = if sort_direction == Some("desc") {
        "DESC"
    } else {
        "ASC"
    };
    let limit = limit.min(1000) as i64;
    let offset = offset as i64;
    let query = format!(
        r#"
          SELECT m.id AS member_id, m.workspace_id AS organization_id,
                 m.user_id, m.role,
                 to_char(m.joined_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS member_created_at,
                 u.name AS user_name, u.email AS user_email, u.image AS user_image
          FROM workspace_member m
          INNER JOIN "user" u ON u.id = m.user_id
          WHERE m.workspace_id = $1
          ORDER BY {sort_column} {sort_direction}
          LIMIT $2 OFFSET $3
        "#
    );
    let rows = state
        .database
        .client
        .query(&query, &[&organization_id, &limit, &offset])
        .await
        .map_err(database_error)?;
    let members = rows
        .iter()
        .map(organization_member_json)
        .collect::<Result<Vec<_>, _>>()?;
    let total = state
        .database
        .client
        .query_one(
            "SELECT COUNT(*)::bigint AS total FROM workspace_member WHERE workspace_id = $1",
            &[&organization_id],
        )
        .await
        .map_err(database_error)?
        .try_get::<_, i64>("total")
        .map_err(database_error)?;
    Ok((members, total))
}

async fn list_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let organization_id = resolve_organization_id(
        &state,
        &auth,
        query.organization_id.as_deref(),
        query.organization_slug.as_deref(),
    )
    .await?;
    require_workspace(&state, &auth, &organization_id).await?;
    let (members, total) = list_organization_members(
        &state,
        &organization_id,
        query.limit.unwrap_or(100),
        query.offset.unwrap_or(0),
        query.sort_by.as_deref(),
        query.sort_direction.as_deref(),
    )
    .await?;
    Ok(Json(json!({ "members": members, "total": total })))
}

async fn get_full_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let organization_id = resolve_organization_id(
        &state,
        &auth,
        query.organization_id.as_deref(),
        query.organization_slug.as_deref(),
    )
    .await?;
    require_workspace(&state, &auth, &organization_id).await?;
    let organization = if query.organization_slug.is_some() {
        state
            .database
            .client
            .query_opt(
                r#"
                  SELECT id, name, slug, logo, metadata, description,
                         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
                  FROM workspace WHERE slug = $1 LIMIT 1
                "#,
                &[&query.organization_slug.as_deref().unwrap_or_default()],
            )
            .await
            .map_err(database_error)?
    } else {
        state
            .database
            .client
            .query_opt(
                r#"
                  SELECT id, name, slug, logo, metadata, description,
                         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
                  FROM workspace WHERE id = $1 LIMIT 1
                "#,
                &[&organization_id],
            )
            .await
            .map_err(database_error)?
    }
    .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Organization not found"))?;
    let metadata = row_optional_string(&organization, "metadata")
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    let (members, _) = list_organization_members(
        &state,
        &organization_id,
        query.members_limit.unwrap_or(100),
        0,
        None,
        None,
    )
    .await?;
    let invitations = state
        .database
        .client
        .query(
            r#"
              SELECT id, workspace_id, email, role, status, inviter_id,
                     to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
              FROM invitation
              WHERE workspace_id = $1
              ORDER BY created_at ASC
            "#,
            &[&organization_id],
        )
        .await
        .map_err(database_error)?
        .into_iter()
        .map(|row| {
            Ok(json!({
                "id": row_string(&row, "id")?,
                "organizationId": row_string(&row, "workspace_id")?,
                "email": row_string(&row, "email")?,
                "role": row_optional_string(&row, "role")?,
                "status": row_string(&row, "status")?,
                "inviterId": row_string(&row, "inviter_id")?,
                "expiresAt": row_string(&row, "expires_at")?,
                "createdAt": row_string(&row, "created_at")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let teams = state
        .database
        .client
        .query(
            r#"
              SELECT id, name, workspace_id,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
              FROM team WHERE workspace_id = $1 ORDER BY created_at ASC
            "#,
            &[&organization_id],
        )
        .await
        .map_err(database_error)?
        .into_iter()
        .map(|row| {
            Ok(json!({
                "id": row_string(&row, "id")?,
                "name": row_string(&row, "name")?,
                "organizationId": row_string(&row, "workspace_id")?,
                "createdAt": row_string(&row, "created_at")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    Ok(Json(json!({
        "id": row_string(&organization, "id")?,
        "name": row_string(&organization, "name")?,
        "slug": row_string(&organization, "slug")?,
        "logo": row_optional_string(&organization, "logo")?,
        "metadata": metadata,
        "description": row_optional_string(&organization, "description")?,
        "createdAt": row_string(&organization, "created_at")?,
        "members": members,
        "invitations": invitations,
        "teams": teams,
    })))
}

fn built_in_permissions(role: &str) -> HashMap<String, Vec<String>> {
    let mut permissions = HashMap::new();
    permissions.insert("organization".to_string(), vec!["update".to_string()]);
    permissions.insert("member".to_string(), Vec::new());
    permissions.insert("invitation".to_string(), Vec::new());
    permissions.insert("team".to_string(), Vec::new());
    permissions.insert("ac".to_string(), vec!["read".to_string()]);
    match role {
        "owner" => {
            permissions.insert(
                "organization".to_string(),
                vec!["update".to_string(), "delete".to_string()],
            );
            permissions.insert(
                "member".to_string(),
                vec![
                    "create".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert(
                "invitation".to_string(),
                vec!["create".to_string(), "cancel".to_string()],
            );
            permissions.insert(
                "team".to_string(),
                vec![
                    "create".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert(
                "ac".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert(
                "project".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "share".to_string(),
                ],
            );
            permissions.insert(
                "task".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "assign".to_string(),
                ],
            );
            permissions.insert(
                "label".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert(
                "workspace".to_string(),
                vec![
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "manage_settings".to_string(),
                ],
            );
        }
        "admin" => {
            permissions.insert(
                "member".to_string(),
                vec![
                    "create".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert(
                "invitation".to_string(),
                vec!["create".to_string(), "cancel".to_string()],
            );
            permissions.insert(
                "team".to_string(),
                vec![
                    "create".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert(
                "ac".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert(
                "project".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "share".to_string(),
                ],
            );
            permissions.insert(
                "task".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "assign".to_string(),
                ],
            );
            permissions.insert(
                "label".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert(
                "workspace".to_string(),
                vec![
                    "read".to_string(),
                    "update".to_string(),
                    "manage_settings".to_string(),
                ],
            );
        }
        "member" => {
            permissions.insert(
                "project".to_string(),
                vec!["create".to_string(), "read".to_string()],
            );
            permissions.insert(
                "task".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                ],
            );
            permissions.insert(
                "label".to_string(),
                vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
            );
            permissions.insert("workspace".to_string(), vec!["read".to_string()]);
        }
        "viewer" => {
            permissions.insert("project".to_string(), vec!["read".to_string()]);
            permissions.insert("task".to_string(), vec!["read".to_string()]);
            permissions.insert("label".to_string(), vec!["read".to_string()]);
            permissions.insert("workspace".to_string(), vec!["read".to_string()]);
        }
        _ => {}
    }
    permissions
}

fn permission_satisfied(
    granted: &HashMap<String, Vec<String>>,
    required: &HashMap<String, Vec<String>>,
) -> bool {
    required.iter().all(|(resource, actions)| {
        granted
            .get(resource)
            .is_some_and(|available| actions.iter().all(|action| available.contains(action)))
    })
}

async fn has_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PermissionInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let organization_id =
        resolve_organization_id(&state, &auth, input.organization_id.as_deref(), None).await?;
    require_workspace(&state, &auth, &organization_id).await?;
    let required = input
        .permissions
        .or(input.permission)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "permissions is required"))?;
    if auth.is_admin() {
        return Ok(Json(json!({ "error": null, "success": true })));
    }
    let role = state
        .database
        .client
        .query_one(
            "SELECT role FROM workspace_member WHERE workspace_id = $1 AND user_id = $2 LIMIT 1",
            &[&organization_id, &auth.user_id],
        )
        .await
        .map_err(database_error)?
        .try_get::<_, String>("role")
        .map_err(database_error)?;
    let granted = state
        .database
        .client
        .query_opt(
            "SELECT permission FROM workspace_role WHERE workspace_id = $1 AND role = $2 LIMIT 1",
            &[&organization_id, &role],
        )
        .await
        .map_err(database_error)?
        .and_then(|row| row_optional_string(&row, "permission").ok().flatten())
        .and_then(|raw| serde_json::from_str::<HashMap<String, Vec<String>>>(&raw).ok())
        .unwrap_or_else(|| built_in_permissions(&role));
    Ok(Json(json!({
        "error": null,
        "success": permission_satisfied(&granted, &required),
    })))
}

async fn notifications_for_user(
    state: &AppState,
    user_id: &str,
    notification_id: Option<&str>,
) -> Result<Value, ApiError> {
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT n.id, n.user_id, n.title, n.content, n.type,
                     n.event_data::text AS event_data,
                     COALESCE(n.is_read, FALSE) AS is_read,
                     n.resource_id, n.resource_type,
                     to_char(n.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(n.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
                     p.id AS project_id, p.workspace_id
              FROM notification n
              LEFT JOIN task t
                ON t.id = n.resource_id AND n.resource_type = 'task'
              LEFT JOIN project p ON p.id = t.project_id
              WHERE n.user_id = $1
                AND ($2::text IS NULL OR n.id = $2)
              ORDER BY n.created_at DESC
              LIMIT 50
            "#,
            &[&user_id, &notification_id],
        )
        .await
        .map_err(database_error)?;
    if notification_id.is_some() && rows.is_empty() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Notification not found",
        ));
    }
    let notifications = rows
        .into_iter()
        .map(|row| {
            let mut event_data = row_optional_string(&row, "event_data")
                .ok()
                .flatten()
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                .unwrap_or(Value::Null);
            let project_id = row_optional_string(&row, "project_id")?;
            let workspace_id = row_optional_string(&row, "workspace_id")?;
            if project_id.is_some() || workspace_id.is_some() {
                let object = event_data.as_object_mut().cloned().unwrap_or_default();
                let mut object = object;
                if let Some(project_id) = project_id {
                    object
                        .entry("projectId".to_string())
                        .or_insert_with(|| Value::String(project_id));
                }
                if let Some(workspace_id) = workspace_id {
                    object
                        .entry("workspaceId".to_string())
                        .or_insert_with(|| Value::String(workspace_id));
                }
                event_data = Value::Object(object);
            }
            Ok(json!({
                "id": row_string(&row, "id")?,
                "userId": row_string(&row, "user_id")?,
                "title": row_optional_string(&row, "title")?,
                "content": row_optional_string(&row, "content")?,
                "type": row_string(&row, "type")?,
                "eventData": event_data,
                "isRead": row.try_get::<_, bool>("is_read").map_err(database_error)?,
                "resourceId": row_optional_string(&row, "resource_id")?,
                "resourceType": row_optional_string(&row, "resource_type")?,
                "createdAt": row_string(&row, "created_at")?,
                "updatedAt": row_string(&row, "updated_at")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    if notification_id.is_some() {
        Ok(notifications.into_iter().next().unwrap_or(Value::Null))
    } else {
        Ok(Value::Array(notifications))
    }
}

async fn list_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    Ok(Json(
        notifications_for_user(&state, &auth.user_id, None).await?,
    ))
}

async fn mark_notification_as_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let updated = state
        .database
        .client
        .execute(
            "UPDATE notification SET is_read = TRUE, updated_at = NOW() WHERE id = $1 AND user_id = $2",
            &[&id, &auth.user_id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Notification not found",
        ));
    }
    Ok(Json(
        notifications_for_user(&state, &auth.user_id, Some(&id)).await?,
    ))
}

async fn mark_all_notifications_as_read(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    state
        .database
        .client
        .execute(
            "UPDATE notification SET is_read = TRUE, updated_at = NOW() WHERE user_id = $1",
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(json!({ "success": true })))
}

async fn clear_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    state
        .database
        .client
        .execute(
            "DELETE FROM notification WHERE user_id = $1",
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(json!({ "success": true })))
}

async fn pending_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let user = state
        .database
        .client
        .query_one(
            "SELECT email, email_verified FROM \"user\" WHERE id = $1 LIMIT 1",
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;
    if !user
        .try_get::<_, bool>("email_verified")
        .map_err(database_error)?
    {
        return Ok(Json(json!([])));
    }
    let email = row_string(&user, "email")?.to_lowercase();
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT i.id, i.email, i.workspace_id, w.name AS workspace_name,
                     u.name AS inviter_name,
                     to_char(i.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     to_char(i.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     i.status
              FROM invitation i
              INNER JOIN workspace w ON w.id = i.workspace_id
              INNER JOIN "user" u ON u.id = i.inviter_id
              WHERE lower(i.email) = $1
                AND i.status = 'pending'
                AND i.expires_at > NOW()
              ORDER BY i.created_at ASC
            "#,
            &[&email],
        )
        .await
        .map_err(database_error)?
        .into_iter()
        .map(|row| {
            Ok(json!({
                "id": row_string(&row, "id")?,
                "email": row_string(&row, "email")?,
                "workspaceId": row_string(&row, "workspace_id")?,
                "workspaceName": row_string(&row, "workspace_name")?,
                "inviterName": row_string(&row, "inviter_name")?,
                "expiresAt": row_string(&row, "expires_at")?,
                "createdAt": row_string(&row, "created_at")?,
                "status": row_string(&row, "status")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(Value::Array(rows)))
}

fn billing_is_enabled() -> bool {
    env_true("KANEO_CLOUD") && env_present("CREEM_API_KEY") && env_present("CREEM_WEBHOOK_SECRET")
}

fn billing_trial_days() -> i32 {
    env::var("BILLING_TRIAL_DAYS")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|days| *days >= 0)
        .unwrap_or(14)
}

async fn get_workspace_billing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let workspace_exists = state
        .database
        .client
        .query_opt(
            "SELECT created_at FROM workspace WHERE id = $1 LIMIT 1",
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    let Some(workspace) = workspace_exists else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Workspace not found"));
    };

    let existing = state
        .database
        .client
        .query_opt(
            "SELECT id FROM workspace_billing WHERE workspace_id = $1 LIMIT 1",
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    if existing.is_none() {
        let founding_free = if let Some(cutoff) = env::var("BILLING_FOUNDING_CUTOFF")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            state
                .database
                .client
                .query_one(
                    "SELECT created_at <= $1::timestamp AS founding_free FROM workspace WHERE id = $2",
                    &[&cutoff, &workspace_id],
                )
                .await
                .map_err(database_error)?
                .try_get::<_, bool>("founding_free")
                .map_err(database_error)?
        } else {
            let _ = workspace;
            false
        };
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO workspace_billing (id, workspace_id, founding_free, trial_ends_at)
                  VALUES ($1, $2, $3,
                    CASE WHEN $3 THEN NULL
                         ELSE NOW() + ($4::int * INTERVAL '1 day')
                    END)
                  ON CONFLICT (workspace_id) DO NOTHING
                "#,
                &[
                    &Uuid::new_v4().to_string(),
                    &workspace_id,
                    &founding_free,
                    &billing_trial_days(),
                ],
            )
            .await
            .map_err(database_error)?;
    }

    let billing = state
        .database
        .client
        .query_one(
            r#"
              SELECT founding_free,
                     to_char(trial_ends_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS trial_ends_at,
                     creem_customer_id, plan, billing_interval, status, seats,
                     to_char(current_period_end AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS current_period_end,
                     to_char(canceled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS canceled_at,
                     (trial_ends_at IS NOT NULL AND trial_ends_at > NOW()) AS trial_active
              FROM workspace_billing
              WHERE workspace_id = $1
              LIMIT 1
            "#,
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    let billing_enabled = billing_is_enabled();
    let founding_free = billing
        .try_get::<_, bool>("founding_free")
        .map_err(database_error)?;
    let status = row_optional_string(&billing, "status")?;
    let trial_active = billing
        .try_get::<_, bool>("trial_active")
        .map_err(database_error)?;
    let (active, reason) = if !billing_enabled {
        (true, "billing_disabled")
    } else if founding_free {
        (true, "founding_free")
    } else if matches!(
        status.as_deref(),
        Some("active" | "trialing" | "past_due" | "scheduled_cancel")
    ) {
        (true, "subscription")
    } else if trial_active {
        (true, "trial")
    } else {
        (false, "expired")
    };
    Ok(Json(json!({
        "billingEnabled": billing_enabled,
        "entitlement": { "active": active, "reason": reason },
        "foundingFree": founding_free,
        "trialEndsAt": row_optional_string(&billing, "trial_ends_at")?,
        "plan": row_optional_string(&billing, "plan")?,
        "billingInterval": row_optional_string(&billing, "billing_interval")?,
        "status": status,
        "seats": billing.try_get::<_, i32>("seats").map_err(database_error)?,
        "currentPeriodEnd": row_optional_string(&billing, "current_period_end")?,
        "canceledAt": row_optional_string(&billing, "canceled_at")?,
        "hasCustomer": row_optional_string(&billing, "creem_customer_id")?.is_some(),
    })))
}

fn build_agent_prompt(input: &StartAgentInput, workspace_id: &str) -> String {
    [
        "You are the autonomous delivery agent for a Kaneo project.",
        &format!("Kaneo workspace ID: {workspace_id}"),
        &format!("Kaneo project ID: {}", input.project_id),
        "",
        "Use the configured Kaneo MCP server as the source of truth for project state.",
        "Start by calling whoami, get_project, and list_tasks for this project.",
        "Choose the next actionable work, make measurable progress, and keep Kaneo updated as you go.",
        "Use the exact status/column IDs returned by Kaneo. Add a concise comment when you start work, when you are blocked, and when you finish.",
        "Do not delete projects, tasks, comments, labels, or relations. Do not claim completion without verification or evidence.",
        "If local files are relevant, work only inside the supplied working directory, inspect the repository first, and run focused checks before marking work complete.",
        "When the goal is complete, summarize the changes, checks, and any remaining blockers in a final Kaneo comment and final response.",
        "",
        "User goal:",
        input.prompt.trim(),
    ]
    .join("\n")
}

fn resolve_agent_cwd(input: &StartAgentInput, run_id: &str) -> Result<PathBuf, ApiError> {
    let cwd = if let Some(cwd) = input
        .cwd
        .as_deref()
        .map(str::trim)
        .filter(|cwd| !cwd.is_empty())
    {
        let path = PathBuf::from(cwd);
        if !path.is_absolute() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "The agent working directory must be an absolute path.",
            ));
        }
        path
    } else {
        PathBuf::from(env::temp_dir())
            .join("kaneo-agent-runs")
            .join(run_id)
    };
    if let Some(root) = env::var_os("KANEO_AGENT_ALLOWED_ROOT") {
        let root = FsPath::new(&root);
        if !cwd.starts_with(root) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("Agent working directory must be inside {}.", root.display()),
            ));
        }
    }
    Ok(cwd)
}

fn agent_response(run: AgentRun) -> AgentRunResponse {
    AgentRunResponse {
        id: run.id,
        workspace_id: run.workspace_id,
        project_id: run.project_id,
        prompt: run.prompt,
        cwd: run.cwd,
        model: run.model,
        network_access: run.network_access,
        status: run.status,
        created_at: run.created_at,
        started_at: run.started_at,
        finished_at: run.finished_at,
        exit_code: run.exit_code,
        error: run.error,
        events: run
            .events
            .into_iter()
            .map(|event| AgentEventResponse {
                at: event.at,
                event_type: event.event_type,
                text: event.text,
            })
            .collect(),
    }
}

async fn start_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<StartAgentInput>,
) -> Result<(StatusCode, Json<AgentRunResponse>), ApiError> {
    if input.project_id.trim().is_empty() || input.prompt.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "projectId and prompt are required",
        ));
    }
    let (auth, workspace_id) = auth_for_project(&state, &headers, &input.project_id).await?;
    let id = Uuid::new_v4().to_string();
    let cwd = resolve_agent_cwd(&input, &id)?;
    if !cwd.is_dir() {
        if input
            .cwd
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "Agent working directory is not a directory: {}",
                    cwd.display()
                ),
            ));
        }
        std::fs::create_dir_all(&cwd).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not create agent working directory: {error}"),
            )
        })?;
    }
    let network_access = input.network_access.unwrap_or(false);
    let mut command_args = vec![
        "exec".to_string(),
        "--json".to_string(),
        "--ephemeral".to_string(),
        "--sandbox".to_string(),
        "workspace-write".to_string(),
        "-C".to_string(),
        cwd.display().to_string(),
        "--skip-git-repo-check".to_string(),
        "-c".to_string(),
        "approval_policy=\"never\"".to_string(),
        "-c".to_string(),
        "mcp_servers.kaneo.bearer_token_env_var=\"KANEO_AGENT_TOKEN\"".to_string(),
        "-c".to_string(),
        "mcp_servers.kaneo.default_tools_approval_mode=\"approve\"".to_string(),
        "-c".to_string(),
        "mcp_servers.kaneo.disabled_tools=[\"delete_project\",\"delete_task\",\"delete_task_comment\",\"delete_label\",\"delete_task_relation\"]".to_string(),
    ];
    if network_access {
        command_args.extend([
            "-c".to_string(),
            "sandbox_workspace_write.network_access=true".to_string(),
        ]);
    }
    if let Some(model) = input
        .model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty())
    {
        command_args.extend(["--model".to_string(), model.to_string()]);
    }
    command_args.push(build_agent_prompt(&input, &workspace_id));

    let mut environment = std::collections::BTreeMap::new();
    environment.insert("KANEO_AGENT_TOKEN".to_string(), auth.credential);
    environment.insert("CODEX_CI".to_string(), "1".to_string());
    environment.insert(
        "KANEO_API_URL".to_string(),
        env::var("KANEO_API_URL").unwrap_or_else(|_| "http://127.0.0.1:1337".to_string()),
    );
    environment.insert("KANEO_WORKSPACE_ID".to_string(), workspace_id.clone());
    environment.insert("KANEO_PROJECT_ID".to_string(), input.project_id.clone());

    let spec = AgentSpec {
        id: Some(id),
        workspace_id,
        project_id: input.project_id.clone(),
        prompt: input.prompt.trim().to_string(),
        cwd,
        model: input.model.clone(),
        network_access,
        command: env::var("KANEO_CODEX_BIN").unwrap_or_else(|_| "codex".to_string()),
        command_args,
        environment,
        max_seconds: input
            .max_seconds
            .unwrap_or(RunnerConfig::default().default_max_seconds),
    };
    let run = state
        .runner
        .start(spec)
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error.to_string()))?;
    Ok((StatusCode::ACCEPTED, Json(agent_response(run))))
}

async fn get_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<AgentRunResponse>, ApiError> {
    let run = state
        .runner
        .get(&id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Agent run not found"))?;
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &run.workspace_id).await?;
    Ok(Json(agent_response(run)))
}

async fn cancel_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<AgentRunResponse>, ApiError> {
    let run = state
        .runner
        .get(&id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Agent run not found"))?;
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &run.workspace_id).await?;
    let cancelled = state
        .runner
        .cancel(&id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Agent run not found"))?;
    Ok(Json(agent_response(cancelled)))
}

async fn project_socket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Query(query): Query<SocketQuery>,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let (auth, _) = auth_for_project(&state, &headers, &project_id).await?;
    let initiator_id = query
        .window_id
        .filter(|value| !value.is_empty())
        .map(|window_id| format!("{}:{window_id}", auth.user_id));
    let receiver = state.events.subscribe();

    Ok(websocket
        .on_upgrade(move |socket| serve_socket(socket, receiver, Some(project_id), initiator_id)))
}

async fn user_socket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SocketQuery>,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let initiator_id = query
        .window_id
        .filter(|value| !value.is_empty())
        .map(|window_id| format!("{}:{window_id}", auth.user_id));
    let receiver = state.events.subscribe();

    Ok(websocket.on_upgrade(move |socket| serve_socket(socket, receiver, None, initiator_id)))
}

async fn serve_socket(
    mut socket: WebSocket,
    mut receiver: broadcast::Receiver<SocketEvent>,
    project_id: Option<String>,
    initiator_id: Option<String>,
) {
    loop {
        tokio::select! {
            incoming = socket.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if text.as_str().contains("\"type\":\"ping\"") {
                            let _ = socket.send(Message::Text("{\"type\":\"pong\"}".into())).await;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(Message::Binary(_))) | Some(Ok(Message::Pong(_))) => {}
                }
            }
            event = receiver.recv() => {
                match event {
                    Ok(event)
                        if project_id.as_ref().is_none_or(|id| event.project_id.as_ref() == Some(id))
                            && event.initiator_id != initiator_id =>
                    {
                        let Ok(payload) = serde_json::to_string(&event) else {
                            continue;
                        };
                        if socket.send(Message::Text(payload.into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn cors(request: Request<Body>, next: Next) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("http://127.0.0.1:5173"));
    if request.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type, authorization, x-api-key, x-kaneo-window-id"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
        );
        return response;
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    response
}

async fn proxy(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Response, ApiError> {
    let Some(legacy_url) = &state.legacy_api_url else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "This Kaneo route has not moved to Rust yet.",
        ));
    };
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", legacy_url.trim_end_matches('/'), path_and_query);
    let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.to_string()))?;
    let incoming_headers = request.headers().clone();
    let body = to_bytes(request.into_body(), DEFAULT_MAX_BODY_BYTES)
        .await
        .map_err(|error| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, error.to_string()))?;
    let mut upstream_request = state.http.request(method, url).body(body);
    for (name, value) in &incoming_headers {
        if *name == header::HOST || *name == header::CONTENT_LENGTH {
            continue;
        }
        upstream_request = upstream_request.header(name.as_str(), value.as_bytes());
    }
    let upstream = upstream_request.send().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Legacy Kaneo API is unavailable: {error}"),
        )
    })?;
    let status = StatusCode::from_u16(upstream.status().as_u16())
        .map_err(|error| ApiError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
    let upstream_headers = upstream.headers().clone();
    let bytes = upstream.bytes().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Could not read legacy Kaneo response: {error}"),
        )
    })?;
    let mut response = Response::builder().status(status);
    for (name, value) in &upstream_headers {
        if *name == header::CONTENT_LENGTH || *name == header::TRANSFER_ENCODING {
            continue;
        }
        response = response.header(name.as_str(), value.as_bytes());
    }
    response
        .body(Body::from(bytes))
        .map_err(|error| ApiError::new(StatusCode::BAD_GATEWAY, error.to_string()))
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/config", get(config))
        .route("/api/rust/status", get(rust_status))
        .route("/api/auth/get-session", get(get_session))
        .route("/api/auth/organization/list", get(list_organizations))
        .route("/api/auth/organization/list-members", get(list_members))
        .route(
            "/api/auth/organization/get-full-organization",
            get(get_full_organization),
        )
        .route(
            "/api/auth/organization/has-permission",
            post(has_permission),
        )
        .route("/api/ws/user", get(user_socket))
        .route("/api/ws/{project_id}", get(project_socket))
        .route("/api/notification", get(list_notifications))
        .route(
            "/api/notification/{id}/read",
            patch(mark_notification_as_read),
        )
        .route(
            "/api/notification/read-all",
            patch(mark_all_notifications_as_read),
        )
        .route("/api/notification/clear-all", delete(clear_notifications))
        .route("/api/invitation/pending", get(pending_invitations))
        .route("/api/billing/{workspace_id}", get(get_workspace_billing))
        .route("/api/label/task/{task_id}", get(list_task_labels))
        .route(
            "/api/label/workspace/{workspace_id}",
            get(list_workspace_labels),
        )
        .route(
            "/api/external-link/task/{task_id}",
            get(list_external_links),
        )
        .route("/api/project", get(list_projects))
        .route("/api/project/{id}", get(get_project))
        .route("/api/column/{project_id}", get(list_columns))
        .route("/api/task/tasks/{project_id}", get(list_tasks))
        .route(
            "/api/task/{id}",
            get(get_task)
                .post(create_task)
                .put(update_task)
                .delete(delete_task),
        )
        .route("/api/task/status/{id}", put(update_task_status))
        .route("/api/task/title/{id}", put(update_task_title))
        .route("/api/task/priority/{id}", put(update_task_priority))
        .route("/api/task/due-date/{id}", put(update_task_due_date))
        .route("/api/agent/runs", post(start_agent))
        .route("/api/agent/runs/{id}", get(get_agent))
        .route("/api/agent/runs/{id}/cancel", post(cancel_agent))
        .fallback(any(proxy))
        .with_state(state)
        .layer(middleware::from_fn(cors))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = env::var("DATABASE_URL")?;
    let database = Database::connect(&database_url).await?;
    let bind = env::var("KANEO_RUST_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let legacy_api_url = env::var("KANEO_LEGACY_API_URL")
        .ok()
        .map(|value| value.trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty());
    let (events, _) = broadcast::channel(512);
    let state = AppState {
        database,
        runner: RunManager::new(RunnerConfig::default()),
        http: reqwest::Client::new(),
        legacy_api_url,
        events,
    };
    let listener = TcpListener::bind(&bind).await?;
    eprintln!("[kaneo-rust-api] listening on http://{bind}");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
