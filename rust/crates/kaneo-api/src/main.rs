//! Rust runtime for the parts of Kaneo that are on the hot path for a local
//! installation: authenticated board reads, task mutations, and autonomous
//! agent execution.
//!
//! The router deliberately has a compatibility fallback. During the
//! migration, routes that have not moved yet are forwarded to the legacy
//! TypeScript API. This lets the Rust process become the single local API
//! origin without pretending that the remaining integration surface has
//! already been ported.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
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
use serde::de::Error as SerdeDeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::IpAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, lookup_host};
use tokio::sync::broadcast;
use tokio_postgres::{Client, NoTls, Row};
use url::Url;
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

#[derive(Debug, Deserialize, Default)]
struct SearchQuery {
    q: Option<String>,
    #[serde(rename = "type")]
    result_type: Option<String>,
    #[serde(rename = "workspaceId")]
    workspace_id: Option<String>,
    #[serde(rename = "projectId")]
    project_id: Option<String>,
    limit: Option<usize>,
    #[serde(rename = "userEmail")]
    _user_email: Option<String>,
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
struct AssigneeInput {
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DescriptionInput {
    description: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MoveTaskInput {
    destination_project_id: String,
    destination_status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkTaskInput {
    task_ids: Vec<String>,
    operation: String,
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportTaskInput {
    title: String,
    description: Option<String>,
    status: String,
    priority: Option<String>,
    start_date: Option<String>,
    due_date: Option<String>,
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportTasksInput {
    tasks: Vec<ImportTaskInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateActivityInput {
    task_id: String,
    user_id: String,
    message: Option<String>,
    #[serde(rename = "type")]
    activity_type: String,
    event_data: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityCommentInput {
    task_id: String,
    comment: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityUpdateCommentInput {
    activity_id: String,
    comment: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityDeleteCommentInput {
    activity_id: String,
}

#[derive(Debug, Deserialize)]
struct CommentContentInput {
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateNotificationInput {
    title: Option<String>,
    message: Option<String>,
    #[serde(rename = "type")]
    notification_type: String,
    event_data: Option<Value>,
    related_entity_id: Option<String>,
    related_entity_type: Option<String>,
}

#[derive(Debug, Clone)]
enum OptionalStringInput {
    Missing,
    Null,
    Value(String),
}

impl Default for OptionalStringInput {
    fn default() -> Self {
        Self::Missing
    }
}

impl<'de> Deserialize<'de> for OptionalStringInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::Null => Ok(Self::Null),
            Value::String(value) => Ok(Self::Value(value)),
            _ => Err(D::Error::custom("expected a string or null")),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateNotificationPreferencesInput {
    email_enabled: Option<bool>,
    ntfy_enabled: Option<bool>,
    #[serde(default)]
    ntfy_server_url: OptionalStringInput,
    #[serde(default)]
    ntfy_topic: OptionalStringInput,
    #[serde(default)]
    ntfy_token: OptionalStringInput,
    gotify_enabled: Option<bool>,
    #[serde(default)]
    gotify_server_url: OptionalStringInput,
    #[serde(default)]
    gotify_token: OptionalStringInput,
    webhook_enabled: Option<bool>,
    #[serde(default)]
    webhook_url: OptionalStringInput,
    #[serde(default)]
    webhook_secret: OptionalStringInput,
    task_assignment_enabled: Option<bool>,
    task_comment_enabled: Option<bool>,
    task_status_change_enabled: Option<bool>,
    due_date_reminder_enabled: Option<bool>,
    due_date_reminder_lead_time_minutes: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationWorkspaceRuleInput {
    is_active: bool,
    email_enabled: bool,
    ntfy_enabled: bool,
    gotify_enabled: bool,
    webhook_enabled: bool,
    project_mode: String,
    selected_project_ids: Option<Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenericWebhookEventsInput {
    task_created: Option<bool>,
    task_status_changed: Option<bool>,
    task_priority_changed: Option<bool>,
    task_title_changed: Option<bool>,
    task_description_changed: Option<bool>,
    task_comment_created: Option<bool>,
    task_deleted: Option<bool>,
    task_moved: Option<bool>,
    task_due_date_changed: Option<bool>,
    task_assignee_changed: Option<bool>,
    task_unassigned: Option<bool>,
    due_date_reminder: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateGenericWebhookInput {
    webhook_url: String,
    secret: Option<String>,
    events: Option<GenericWebhookEventsInput>,
    due_date_reminder_lead_time_minutes: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateGenericWebhookInput {
    webhook_url: Option<String>,
    #[serde(default)]
    secret: OptionalStringInput,
    is_active: Option<bool>,
    events: Option<GenericWebhookEventsInput>,
    due_date_reminder_lead_time_minutes: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskRelationInput {
    source_task_id: String,
    target_task_id: String,
    relation_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTimeEntryInput {
    task_id: String,
    start_time: String,
    end_time: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTimeEntryInput {
    start_time: String,
    end_time: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateProjectInput {
    name: String,
    workspace_id: String,
    icon: String,
    slug: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProjectInput {
    name: String,
    icon: String,
    slug: String,
    description: String,
    is_public: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateColumnInput {
    name: String,
    icon: Option<String>,
    color: Option<String>,
    is_final: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ColumnPositionInput {
    id: String,
    position: i32,
}

#[derive(Debug, Deserialize)]
struct ReorderColumnsInput {
    columns: Vec<ColumnPositionInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateColumnInput {
    name: Option<String>,
    icon: Option<Option<String>>,
    color: Option<Option<String>>,
    is_final: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateLabelInput {
    name: String,
    color: String,
    workspace_id: String,
    task_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateLabelInput {
    name: String,
    color: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachLabelInput {
    task_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowRuleInput {
    integration_type: String,
    event_type: String,
    column_id: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SearchResult {
    id: String,
    #[serde(rename = "type")]
    result_type: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_name: Option<String>,
    created_at: String,
    relevance_score: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivityRecord {
    id: String,
    task_id: String,
    #[serde(rename = "type")]
    activity_type: String,
    created_at: String,
    updated_at: String,
    user_id: Option<String>,
    content: Option<String>,
    event_data: Value,
    external_user_name: Option<String>,
    external_user_avatar: Option<String>,
    external_source: Option<String>,
    external_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommentRecord {
    id: String,
    task_id: String,
    user_id: String,
    content: String,
    created_at: String,
    updated_at: String,
    user: CommentUser,
}

#[derive(Debug, Serialize)]
struct CommentUser {
    name: Option<String>,
    image: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TaskRelationRecord {
    id: String,
    source_task_id: String,
    target_task_id: String,
    relation_type: String,
    created_at: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RelationTask {
    id: String,
    title: String,
    status: String,
    priority: Option<String>,
    number: Option<i32>,
    project_id: String,
    user_id: Option<String>,
    assignee_name: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TaskRelationWithTasks {
    id: String,
    source_task_id: String,
    target_task_id: String,
    relation_type: String,
    created_at: String,
    source_task: RelationTask,
    target_task: RelationTask,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TimeEntryRecord {
    id: String,
    task_id: String,
    user_id: Option<String>,
    description: Option<String>,
    start_time: String,
    end_time: Option<String>,
    duration: Option<i32>,
    created_at: String,
    updated_at: String,
    user_name: Option<String>,
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

fn publish_relation_event(
    state: &AppState,
    event_type: &str,
    project_id: impl Into<String>,
    source_task_id: impl Into<String>,
    target_task_id: impl Into<String>,
    auth: &AuthContext,
    headers: &HeaderMap,
) {
    let _ = state.events.send(SocketEvent {
        event_type: event_type.to_string(),
        project_id: Some(project_id.into()),
        task_id: None,
        source_task_id: Some(source_task_id.into()),
        target_task_id: Some(target_task_id.into()),
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

async fn require_workspace_permission(
    state: &AppState,
    auth: &AuthContext,
    workspace_id: &str,
    resource: &str,
    action: &str,
) -> Result<(), ApiError> {
    require_workspace(state, auth, workspace_id).await?;
    if auth.is_admin() {
        return Ok(());
    }

    let role = state
        .database
        .client
        .query_opt(
            "SELECT role FROM workspace_member WHERE workspace_id = $1 AND user_id = $2 LIMIT 1",
            &[&workspace_id, &auth.user_id],
        )
        .await
        .map_err(database_error)?
        .and_then(|row| row.try_get::<_, String>("role").ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "You don't have access to this workspace",
            )
        })?;

    let granted = state
        .database
        .client
        .query_opt(
            "SELECT permission FROM workspace_role WHERE workspace_id = $1 AND role = $2 LIMIT 1",
            &[&workspace_id, &role],
        )
        .await
        .map_err(database_error)?
        .and_then(|row| row_optional_string(&row, "permission").ok().flatten())
        .and_then(|raw| serde_json::from_str::<HashMap<String, Vec<String>>>(&raw).ok())
        .unwrap_or_else(|| built_in_permissions(&role));

    let allowed = granted
        .get(resource)
        .is_some_and(|actions| actions.iter().any(|value| value == action));
    if allowed {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Insufficient permissions",
        ))
    }
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

async fn instance_status(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let has_users = state
        .database
        .client
        .query_one("SELECT COUNT(*)::bigint AS count FROM \"user\"", &[])
        .await
        .map_err(database_error)?
        .try_get::<_, i64>("count")
        .map_err(database_error)?
        > 0;
    let has_admin = state
        .database
        .client
        .query_one(
            "SELECT COUNT(*)::bigint AS count FROM \"user\" WHERE role = 'admin'",
            &[],
        )
        .await
        .map_err(database_error)?
        .try_get::<_, i64>("count")
        .map_err(database_error)?
        > 0;
    Ok(Json(json!({
        "hasUsers": has_users,
        "hasAdmin": has_admin,
    })))
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

async fn project_record(
    state: &AppState,
    project_id: &str,
    workspace_id: &str,
) -> Result<Value, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT p.id, p.workspace_id, p.slug, p.icon, p.name, p.description,
                     to_char(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     COALESCE(p.is_public, FALSE) AS is_public,
                     to_char(p.archived_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS archived_at
              FROM project p
              WHERE p.id = $1 AND p.workspace_id = $2
              LIMIT 1
            "#,
            &[&project_id, &workspace_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Project not found"))?;
    Ok(json!({
        "id": row_string(&row, "id")?,
        "workspaceId": row_string(&row, "workspace_id")?,
        "slug": row_string(&row, "slug")?,
        "icon": row_optional_string(&row, "icon")?,
        "name": row_string(&row, "name")?,
        "description": row_optional_string(&row, "description")?,
        "createdAt": row_string(&row, "created_at")?,
        "isPublic": row.try_get::<_, bool>("is_public").map_err(database_error)?,
        "archivedAt": row_optional_string(&row, "archived_at")?,
    }))
}

async fn create_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateProjectInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &input.workspace_id).await?;
    let id = Uuid::new_v4().to_string();
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO project
                (id, workspace_id, slug, icon, name, description, is_public, last_task_number)
              VALUES ($1, $2, $3, $4, $5, NULL, FALSE, 0)
            "#,
            &[
                &id,
                &input.workspace_id,
                &input.slug,
                &input.icon,
                &input.name,
            ],
        )
        .await
        .map_err(database_error)?;
    for (name, slug, position, is_final) in [
        ("To Do", "to-do", 0_i32, false),
        ("In Progress", "in-progress", 1_i32, false),
        ("In Review", "in-review", 2_i32, false),
        ("Done", "done", 3_i32, true),
    ] {
        let column_id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO "column"
                    (id, project_id, name, slug, position, icon, color, is_final, created_at, updated_at)
                  VALUES ($1, $2, $3, $4, $5, NULL, NULL, $6, NOW(), NOW())
                "#,
                &[&column_id, &id, &name, &slug, &position, &is_final],
            )
            .await
            .map_err(database_error)?;
    }
    Ok(Json(
        project_record(&state, &id, &input.workspace_id).await?,
    ))
}

async fn update_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateProjectInput>,
) -> Result<Json<Value>, ApiError> {
    let (_, workspace_id) = auth_for_project(&state, &headers, &id).await?;
    let updated = state
        .database
        .client
        .execute(
            r#"
              UPDATE project
              SET name = $1, icon = $2, slug = $3, description = $4,
                  is_public = $5
              WHERE id = $6 AND workspace_id = $7
            "#,
            &[
                &input.name,
                &input.icon,
                &input.slug,
                &input.description,
                &input.is_public,
                &id,
                &workspace_id,
            ],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Project not found"));
    }
    Ok(Json(project_record(&state, &id, &workspace_id).await?))
}

async fn archive_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (_, workspace_id) = auth_for_project(&state, &headers, &id).await?;
    let updated = state
        .database
        .client
        .execute(
            "UPDATE project SET archived_at = NOW() WHERE id = $1 AND workspace_id = $2",
            &[&id, &workspace_id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Project not found"));
    }
    Ok(Json(project_record(&state, &id, &workspace_id).await?))
}

async fn unarchive_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (_, workspace_id) = auth_for_project(&state, &headers, &id).await?;
    let updated = state
        .database
        .client
        .execute(
            "UPDATE project SET archived_at = NULL WHERE id = $1 AND workspace_id = $2",
            &[&id, &workspace_id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Project not found"));
    }
    Ok(Json(project_record(&state, &id, &workspace_id).await?))
}

async fn delete_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (_, workspace_id) = auth_for_project(&state, &headers, &id).await?;
    let existing = project_record(&state, &id, &workspace_id).await?;
    let deleted = state
        .database
        .client
        .execute(
            "DELETE FROM project WHERE id = $1 AND workspace_id = $2",
            &[&id, &workspace_id],
        )
        .await
        .map_err(database_error)?;
    if deleted == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Project not found"));
    }
    Ok(Json(existing))
}

fn column_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut previous_dash = false;
    for character in name.trim().chars() {
        for lower in character.to_lowercase() {
            if lower.is_alphanumeric() {
                slug.push(lower);
                previous_dash = false;
            } else if !slug.is_empty() && !previous_dash {
                slug.push('-');
                previous_dash = true;
            }
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug
}

fn column_from_row(row: &Row) -> Result<Value, ApiError> {
    Ok(json!({
        "id": row_string(row, "id")?,
        "projectId": row_string(row, "project_id")?,
        "name": row_string(row, "name")?,
        "slug": row_string(row, "slug")?,
        "position": row.try_get::<_, i32>("position").map_err(database_error)?,
        "icon": row_optional_string(row, "icon")?,
        "color": row_optional_string(row, "color")?,
        "isFinal": row.try_get::<_, bool>("is_final").map_err(database_error)?,
        "createdAt": row_string(row, "created_at")?,
        "updatedAt": row_string(row, "updated_at")?,
    }))
}

const COLUMN_SELECT_SQL: &str = r#"
    SELECT id, project_id, name, slug, position, icon, color, is_final,
           to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
           to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
    FROM "column"
"#;

async fn column_by_id(state: &AppState, column_id: &str) -> Result<Value, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            &format!("{COLUMN_SELECT_SQL} WHERE id = $1 LIMIT 1"),
            &[&column_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Column not found"))?;
    column_from_row(&row)
}

async fn column_context(state: &AppState, column_id: &str) -> Result<String, ApiError> {
    state
        .database
        .client
        .query_opt(
            "SELECT project_id FROM \"column\" WHERE id = $1 LIMIT 1",
            &[&column_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_string(&row, "project_id"))
        .transpose()?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Column not found"))
}

async fn create_column(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<CreateColumnInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, _) = auth_for_project(&state, &headers, &project_id).await?;
    let slug = column_slug(&input.name);
    if slug.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Column name must contain at least one alphanumeric character",
        ));
    }
    if matches!(slug.as_str(), "planned" | "archived") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("Column slug \"{slug}\" is reserved for virtual task statuses"),
        ));
    }
    let duplicate = state
        .database
        .client
        .query_opt(
            "SELECT id FROM \"column\" WHERE project_id = $1 AND slug = $2 LIMIT 1",
            &[&project_id, &slug],
        )
        .await
        .map_err(database_error)?;
    if duplicate.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("Column with slug \"{slug}\" already exists in this project"),
        ));
    }
    let position: i32 = state
        .database
        .client
        .query_one(
            "SELECT COALESCE(MAX(position), -1) + 1 AS position FROM \"column\" WHERE project_id = $1",
            &[&project_id],
        )
        .await
        .map_err(database_error)?
        .try_get("position")
        .map_err(database_error)?;
    let id = Uuid::new_v4().to_string();
    let icon = input.icon.unwrap_or_default();
    let color = input.color.unwrap_or_default();
    let is_final = input.is_final.unwrap_or(false);
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO "column"
                (id, project_id, name, slug, position, icon, color, is_final, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), $8, NOW(), NOW())
            "#,
            &[
                &id,
                &project_id,
                &input.name,
                &slug,
                &position,
                &icon,
                &color,
                &is_final,
            ],
        )
        .await
        .map_err(database_error)?;
    publish_task_event(
        &state,
        "TASK_UPDATED",
        project_id.clone(),
        id.clone(),
        &auth,
        &headers,
    );
    Ok(Json(column_by_id(&state, &id).await?))
}

async fn reorder_columns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<ReorderColumnsInput>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let _ = auth_for_project(&state, &headers, &project_id).await?;
    for column in input.columns {
        let updated = state
            .database
            .client
            .execute(
                "UPDATE \"column\" SET position = $1, updated_at = NOW() WHERE id = $2 AND project_id = $3",
                &[&column.position, &column.id, &project_id],
            )
            .await
            .map_err(database_error)?;
        if updated == 0 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("Column {} does not belong to this project", column.id),
            ));
        }
    }
    let rows = state
        .database
        .client
        .query(
            &format!("{COLUMN_SELECT_SQL} WHERE project_id = $1 ORDER BY position ASC"),
            &[&project_id],
        )
        .await
        .map_err(database_error)?;
    let columns = rows
        .iter()
        .map(column_from_row)
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(columns))
}

async fn update_column(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateColumnInput>,
) -> Result<Json<Value>, ApiError> {
    let project_id = column_context(&state, &id).await?;
    let (auth, _) = auth_for_project(&state, &headers, &project_id).await?;
    let existing = state
        .database
        .client
        .query_one(
            "SELECT name, icon, color, is_final FROM \"column\" WHERE id = $1",
            &[&id],
        )
        .await
        .map_err(database_error)?;
    let name = input.name.unwrap_or(row_string(&existing, "name")?);
    let icon = input
        .icon
        .unwrap_or(row_optional_string(&existing, "icon")?);
    let color = input
        .color
        .unwrap_or(row_optional_string(&existing, "color")?);
    let is_final = input
        .is_final
        .unwrap_or(existing.try_get("is_final").map_err(database_error)?);
    state
        .database
        .client
        .execute(
            "UPDATE \"column\" SET name = $1, icon = $2, color = $3, is_final = $4, updated_at = NOW() WHERE id = $5",
            &[&name, &icon, &color, &is_final, &id],
        )
        .await
        .map_err(database_error)?;
    publish_task_event(
        &state,
        "TASK_UPDATED",
        project_id,
        id.clone(),
        &auth,
        &headers,
    );
    Ok(Json(column_by_id(&state, &id).await?))
}

async fn delete_column(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let project_id = column_context(&state, &id).await?;
    let (auth, _) = auth_for_project(&state, &headers, &project_id).await?;
    let existing = column_by_id(&state, &id).await?;
    let task_count: i64 = state
        .database
        .client
        .query_one(
            "SELECT COUNT(*)::bigint AS count FROM task WHERE column_id = $1",
            &[&id],
        )
        .await
        .map_err(database_error)?
        .try_get("count")
        .map_err(database_error)?;
    if task_count > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Cannot delete column that contains tasks. Move or delete tasks first.",
        ));
    }
    state
        .database
        .client
        .execute("DELETE FROM \"column\" WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?;
    publish_task_event(&state, "TASK_UPDATED", project_id, id, &auth, &headers);
    Ok(Json(existing))
}

fn label_from_row(row: &Row) -> Result<Value, ApiError> {
    Ok(json!({
        "id": row_string(row, "id")?,
        "name": row_string(row, "name")?,
        "color": row_string(row, "color")?,
        "createdAt": row_string(row, "created_at")?,
        "updatedAt": row_string(row, "updated_at")?,
        "taskId": row_optional_string(row, "task_id")?,
        "workspaceId": row_optional_string(row, "workspace_id")?,
    }))
}

const LABEL_SELECT_SQL: &str = r#"
    SELECT id, name, color,
           to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
           to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
           task_id, workspace_id
    FROM label
"#;

async fn label_by_id(state: &AppState, label_id: &str) -> Result<Value, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            &format!("{LABEL_SELECT_SQL} WHERE id = $1 LIMIT 1"),
            &[&label_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Label not found"))?;
    label_from_row(&row)
}

async fn label_context(
    state: &AppState,
    label_id: &str,
) -> Result<(String, Option<String>, String), ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT l.task_id, COALESCE(l.workspace_id, p.workspace_id) AS workspace_id
              FROM label l
              LEFT JOIN task t ON t.id = l.task_id
              LEFT JOIN project p ON p.id = t.project_id
              WHERE l.id = $1
              LIMIT 1
            "#,
            &[&label_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Label not found"))?;
    Ok((
        row_string(&row, "workspace_id")?,
        row_optional_string(&row, "task_id")?,
        label_id.to_string(),
    ))
}

async fn create_label(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateLabelInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &input.workspace_id).await?;
    let workspace_id = if let Some(task_id) = input.task_id.as_deref() {
        let task_workspace_id = task_workspace(&state.database, task_id).await?;
        if task_workspace_id != input.workspace_id {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "Task not found"));
        }
        task_workspace_id
    } else {
        input.workspace_id.clone()
    };
    let existing = if let Some(task_id) = input.task_id.as_deref() {
        state
            .database
            .client
            .query_opt(
                "SELECT id FROM label WHERE task_id = $1 AND name = $2 LIMIT 1",
                &[&task_id, &input.name],
            )
            .await
            .map_err(database_error)?
    } else {
        state
            .database
            .client
            .query_opt(
                "SELECT id FROM label WHERE workspace_id = $1 AND name = $2 AND task_id IS NULL LIMIT 1",
                &[&workspace_id, &input.name],
            )
            .await
            .map_err(database_error)?
    };
    if let Some(existing) = existing {
        return Ok(Json(
            label_by_id(&state, &row_string(&existing, "id")?).await?,
        ));
    }
    let id = Uuid::new_v4().to_string();
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO label
                (id, name, color, created_at, updated_at, task_id, workspace_id)
              VALUES ($1, $2, $3, NOW(), NOW(), $4, $5)
            "#,
            &[
                &id,
                &input.name,
                &input.color,
                &input.task_id,
                &workspace_id,
            ],
        )
        .await
        .map_err(database_error)?;
    if let Some(task_id) = input.task_id {
        let task = task_by_id(&state.database, &task_id).await?;
        publish_task_event(
            &state,
            "TASK_LABEL_UPDATED",
            task.project_id,
            task_id,
            &auth,
            &headers,
        );
    }
    Ok(Json(label_by_id(&state, &id).await?))
}

async fn get_label(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (workspace_id, _, _) = label_context(&state, &id).await?;
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    Ok(Json(label_by_id(&state, &id).await?))
}

async fn update_label(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateLabelInput>,
) -> Result<Json<Value>, ApiError> {
    let (workspace_id, task_id, _) = label_context(&state, &id).await?;
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let existing = state
        .database
        .client
        .query_one("SELECT name FROM label WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?;
    let previous_name = row_string(&existing, "name")?;
    state
        .database
        .client
        .execute(
            "UPDATE label SET name = $1, color = $2, updated_at = NOW() WHERE id = $3",
            &[&input.name, &input.color, &id],
        )
        .await
        .map_err(database_error)?;
    if task_id.is_none() {
        state
            .database
            .client
            .execute(
                "UPDATE label SET name = $1, color = $2, updated_at = NOW() WHERE workspace_id = $3 AND name = $4 AND task_id IS NOT NULL",
                &[&input.name, &input.color, &workspace_id, &previous_name],
            )
            .await
            .map_err(database_error)?;
    }
    if let Some(task_id) = task_id {
        let task = task_by_id(&state.database, &task_id).await?;
        publish_task_event(
            &state,
            "TASK_LABEL_UPDATED",
            task.project_id,
            task_id,
            &auth,
            &headers,
        );
    }
    Ok(Json(label_by_id(&state, &id).await?))
}

async fn assign_label_to_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<AttachLabelInput>,
) -> Result<Json<Value>, ApiError> {
    let (workspace_id, _, _) = label_context(&state, &id).await?;
    let (auth, _) = auth_for_task(&state, &headers, &input.task_id).await?;
    let target_workspace = task_workspace(&state.database, &input.task_id).await?;
    if target_workspace != workspace_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Label and task must belong to the same workspace",
        ));
    }
    state
        .database
        .client
        .execute(
            "UPDATE label SET task_id = $1, updated_at = NOW() WHERE id = $2",
            &[&input.task_id, &id],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &input.task_id).await?;
    publish_task_event(
        &state,
        "TASK_LABEL_UPDATED",
        task.project_id,
        input.task_id,
        &auth,
        &headers,
    );
    Ok(Json(label_by_id(&state, &id).await?))
}

async fn unassign_label_from_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (workspace_id, task_id, _) = label_context(&state, &id).await?;
    let Some(task_id) = task_id else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Label is not assigned to a task",
        ));
    };
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    state
        .database
        .client
        .execute(
            "UPDATE label SET task_id = NULL, updated_at = NOW() WHERE id = $1",
            &[&id],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &task_id).await?;
    publish_task_event(
        &state,
        "TASK_LABEL_UPDATED",
        task.project_id,
        task_id,
        &auth,
        &headers,
    );
    Ok(Json(label_by_id(&state, &id).await?))
}

async fn delete_label(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (workspace_id, task_id, _) = label_context(&state, &id).await?;
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let existing = label_by_id(&state, &id).await?;
    if let Some(task_id) = task_id {
        state
            .database
            .client
            .execute("DELETE FROM label WHERE id = $1", &[&id])
            .await
            .map_err(database_error)?;
        let task = task_by_id(&state.database, &task_id).await?;
        publish_task_event(
            &state,
            "TASK_LABEL_UPDATED",
            task.project_id,
            task_id,
            &auth,
            &headers,
        );
    } else {
        let name: String = state
            .database
            .client
            .query_one("SELECT name FROM label WHERE id = $1", &[&id])
            .await
            .map_err(database_error)?
            .try_get("name")
            .map_err(database_error)?;
        state
            .database
            .client
            .execute(
                "DELETE FROM label WHERE workspace_id = $1 AND name = $2",
                &[&workspace_id, &name],
            )
            .await
            .map_err(database_error)?;
    }
    Ok(Json(existing))
}

fn generic_webhook_default_events() -> serde_json::Map<String, Value> {
    [
        ("taskCreated", true),
        ("taskStatusChanged", true),
        ("taskPriorityChanged", false),
        ("taskTitleChanged", false),
        ("taskDescriptionChanged", false),
        ("taskCommentCreated", true),
        ("taskDeleted", false),
        ("taskMoved", false),
        ("taskDueDateChanged", false),
        ("taskAssigneeChanged", false),
        ("taskUnassigned", false),
        ("dueDateReminder", false),
    ]
    .into_iter()
    .map(|(name, enabled)| (name.to_string(), Value::Bool(enabled)))
    .collect()
}

fn normalize_generic_webhook_config(config: &mut Value) -> Result<(), ApiError> {
    let object = config.as_object_mut().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook integration config must be an object",
        )
    })?;

    match object.get("secret").and_then(Value::as_str) {
        Some(secret) if !secret.trim().is_empty() => {
            object.insert(
                "secret".to_string(),
                Value::String(secret.trim().to_string()),
            );
        }
        _ => {
            object.remove("secret");
        }
    }

    let mut events = generic_webhook_default_events();
    if let Some(existing_events) = object.get("events").and_then(Value::as_object) {
        for (name, value) in existing_events {
            if value.is_boolean() {
                events.insert(name.clone(), value.clone());
            }
        }
    }
    object.insert("events".to_string(), Value::Object(events));
    if object
        .get("dueDateReminderLeadTimeMinutes")
        .is_none_or(Value::is_null)
    {
        object.insert(
            "dueDateReminderLeadTimeMinutes".to_string(),
            Value::Number(1440.into()),
        );
    }
    Ok(())
}

async fn validate_generic_webhook_config(config: &Value) -> Result<(), ApiError> {
    let object = config.as_object().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook integration config must be an object",
        )
    })?;
    let webhook_url = object
        .get("webhookUrl")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Webhook URL is required"))?;
    validate_notification_destination(webhook_url)
        .await
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.message))?;
    let due_date_lead_time = object
        .get("dueDateReminderLeadTimeMinutes")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "dueDateReminderLeadTimeMinutes must be an integer",
            )
        })?;
    if !(5..=43_200).contains(&due_date_lead_time) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "dueDateReminderLeadTimeMinutes must be between 5 and 43200",
        ));
    }
    Ok(())
}

fn merge_generic_webhook_events(
    config: &mut Value,
    events: &GenericWebhookEventsInput,
) -> Result<(), ApiError> {
    let value = serde_json::to_value(events).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid generic webhook events: {error}"),
        )
    })?;
    let config_object = config.as_object_mut().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook integration config must be an object",
        )
    })?;
    let event_object = config_object
        .entry("events".to_string())
        .or_insert_with(|| Value::Object(generic_webhook_default_events()));
    let event_object = event_object.as_object_mut().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook events must be an object",
        )
    })?;
    if let Some(updates) = value.as_object() {
        for (name, value) in updates {
            if !value.is_null() {
                event_object.insert(name.clone(), value.clone());
            }
        }
    }
    Ok(())
}

async fn generic_webhook_row(state: &AppState, project_id: &str) -> Result<Option<Row>, ApiError> {
    state
        .database
        .client
        .query_opt(
            r#"
              SELECT id, project_id, config, is_active,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM integration
              WHERE project_id = $1 AND type = 'generic-webhook'
              LIMIT 1
            "#,
            &[&project_id],
        )
        .await
        .map_err(database_error)
}

fn generic_webhook_response(row: &Row) -> Result<Value, ApiError> {
    let mut config =
        serde_json::from_str::<Value>(&row_string(row, "config")?).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid generic webhook integration config: {error}"),
            )
        })?;
    normalize_generic_webhook_config(&mut config)?;
    let object = config.as_object().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Generic webhook integration config must be an object",
        )
    })?;
    let webhook_url = object
        .get("webhookUrl")
        .and_then(Value::as_str)
        .map(str::to_string);
    let secret = object
        .get("secret")
        .and_then(Value::as_str)
        .map(str::to_string);
    let due_date_lead_time = object
        .get("dueDateReminderLeadTimeMinutes")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or(1440);

    Ok(json!({
        "id": row_string(row, "id")?,
        "projectId": row_string(row, "project_id")?,
        "webhookConfigured": webhook_url.is_some(),
        "maskedWebhookUrl": mask_notification_secret(webhook_url.as_ref()),
        "secretConfigured": secret.is_some(),
        "maskedSecret": mask_notification_secret(secret.as_ref()),
        "events": object.get("events").cloned().unwrap_or_else(|| Value::Object(generic_webhook_default_events())),
        "dueDateReminderLeadTimeMinutes": due_date_lead_time,
        "isActive": row.try_get::<_, Option<bool>>("is_active").map_err(database_error)?,
        "createdAt": row_string(row, "created_at")?,
        "updatedAt": row_string(row, "updated_at")?,
    }))
}

async fn get_generic_webhook_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (_auth, _workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    let integration = generic_webhook_row(&state, &project_id).await?;
    Ok(Json(
        integration
            .as_ref()
            .map(generic_webhook_response)
            .transpose()?
            .unwrap_or(Value::Null),
    ))
}

async fn create_generic_webhook_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<CreateGenericWebhookInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let mut config = json!({ "webhookUrl": input.webhook_url });
    if let Some(secret) = input.secret.as_deref() {
        if let Some(secret) = normalize_notification_string(Some(secret)) {
            config["secret"] = Value::String(secret);
        }
    }
    if let Some(events) = input.events.as_ref() {
        merge_generic_webhook_events(&mut config, events)?;
    }
    if let Some(lead_time) = input.due_date_reminder_lead_time_minutes {
        config["dueDateReminderLeadTimeMinutes"] = Value::Number(lead_time.into());
    }
    normalize_generic_webhook_config(&mut config)?;
    validate_generic_webhook_config(&config).await?;
    let serialized_config = config.to_string();
    if let Some(existing) = generic_webhook_row(&state, &project_id).await? {
        let integration_id = row_string(&existing, "id")?;
        state
            .database
            .client
            .execute(
                "UPDATE integration SET config = $2, is_active = TRUE, updated_at = NOW() WHERE id = $1",
                &[&integration_id, &serialized_config],
            )
            .await
            .map_err(database_error)?;
    } else {
        let integration_id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO integration
                    (id, project_id, type, config, is_active, created_at, updated_at)
                  VALUES ($1, $2, 'generic-webhook', $3, TRUE, NOW(), NOW())
                "#,
                &[&integration_id, &project_id, &serialized_config],
            )
            .await
            .map_err(database_error)?;
    }
    let integration = generic_webhook_row(&state, &project_id)
        .await?
        .ok_or_else(|| database_error("Generic webhook integration was not saved"))?;
    Ok(Json(generic_webhook_response(&integration)?))
}

async fn update_generic_webhook_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<UpdateGenericWebhookInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let existing = generic_webhook_row(&state, &project_id)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "Generic webhook integration not found",
            )
        })?;
    let mut config =
        serde_json::from_str::<Value>(&row_string(&existing, "config")?).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid generic webhook integration config: {error}"),
            )
        })?;
    normalize_generic_webhook_config(&mut config)?;
    if let Some(webhook_url) = input.webhook_url.as_deref() {
        if !webhook_url.trim().is_empty() {
            config["webhookUrl"] = Value::String(webhook_url.trim().to_string());
        }
    }
    if !matches!(&input.secret, OptionalStringInput::Missing) {
        match &input.secret {
            OptionalStringInput::Value(secret) => {
                match normalize_notification_string(Some(secret)) {
                    Some(secret) => config["secret"] = Value::String(secret),
                    None => {
                        if let Some(object) = config.as_object_mut() {
                            object.remove("secret");
                        }
                    }
                }
            }
            OptionalStringInput::Null => {
                if let Some(object) = config.as_object_mut() {
                    object.remove("secret");
                }
            }
            OptionalStringInput::Missing => {}
        }
    }
    if let Some(events) = input.events.as_ref() {
        merge_generic_webhook_events(&mut config, events)?;
    }
    if let Some(lead_time) = input.due_date_reminder_lead_time_minutes {
        config["dueDateReminderLeadTimeMinutes"] = Value::Number(lead_time.into());
    }
    normalize_generic_webhook_config(&mut config)?;
    validate_generic_webhook_config(&config).await?;
    let serialized_config = config.to_string();
    let integration_id = row_string(&existing, "id")?;
    let active = input
        .is_active
        .or_else(|| {
            existing
                .try_get::<_, Option<bool>>("is_active")
                .ok()
                .flatten()
        })
        .unwrap_or(true);
    state
        .database
        .client
        .execute(
            "UPDATE integration SET config = $2, is_active = $3, updated_at = NOW() WHERE id = $1",
            &[&integration_id, &serialized_config, &active],
        )
        .await
        .map_err(database_error)?;
    let integration = generic_webhook_row(&state, &project_id)
        .await?
        .ok_or_else(|| database_error("Generic webhook integration was not saved"))?;
    Ok(Json(generic_webhook_response(&integration)?))
}

async fn delete_generic_webhook_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let existing = generic_webhook_row(&state, &project_id)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "Generic webhook integration not found",
            )
        })?;
    let integration_id = row_string(&existing, "id")?;
    state
        .database
        .client
        .execute("DELETE FROM integration WHERE id = $1", &[&integration_id])
        .await
        .map_err(database_error)?;
    Ok(Json(json!({ "success": true })))
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

async fn get_public_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<BoardQuery>,
) -> Result<Json<BoardResponse>, ApiError> {
    let board = load_board(&state, &id, &query).await?;
    if !board.data.is_public {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Project is not public",
        ));
    }
    Ok(Json(board))
}

async fn list_workspace_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT u.id, u.name, u.email, u.image, m.role
              FROM workspace_member m
              INNER JOIN "user" u ON u.id = m.user_id
              WHERE m.workspace_id = $1
              ORDER BY u.name ASC, u.email ASC
            "#,
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    rows.into_iter()
        .map(|row| {
            Ok(json!({
                "id": row_string(&row, "id")?,
                "name": row_string(&row, "name")?,
                "email": row_string(&row, "email")?,
                "image": row_optional_string(&row, "image")?,
                "role": row_string(&row, "role")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()
        .map(Json)
}

fn search_task_from_row(row: &Row, relevance_score: i32) -> Result<SearchResult, ApiError> {
    Ok(SearchResult {
        id: row_string(row, "id")?,
        result_type: "task".to_string(),
        title: row_string(row, "title")?,
        description: row_optional_string(row, "description")?,
        content: None,
        project_id: row_optional_string(row, "project_id")?,
        project_name: row_optional_string(row, "project_name")?,
        workspace_id: row_optional_string(row, "workspace_id")?,
        workspace_name: row_optional_string(row, "workspace_name")?,
        user_id: row_optional_string(row, "user_id")?,
        user_name: row_optional_string(row, "user_name")?,
        created_at: row_string(row, "created_at")?,
        relevance_score,
        task_number: row_optional_i32(row, "task_number")?,
        project_slug: row_optional_string(row, "project_slug")?,
        priority: row_optional_string(row, "priority")?,
        status: row_optional_string(row, "status")?,
    })
}

fn search_project_from_row(row: &Row, relevance_score: i32) -> Result<SearchResult, ApiError> {
    Ok(SearchResult {
        id: row_string(row, "id")?,
        result_type: "project".to_string(),
        title: row_string(row, "name")?,
        description: row_optional_string(row, "description")?,
        content: None,
        project_id: Some(row_string(row, "id")?),
        project_name: row_optional_string(row, "name")?,
        workspace_id: row_optional_string(row, "workspace_id")?,
        workspace_name: row_optional_string(row, "workspace_name")?,
        user_id: None,
        user_name: None,
        created_at: row_string(row, "created_at")?,
        relevance_score,
        task_number: None,
        project_slug: row_optional_string(row, "slug")?,
        priority: None,
        status: None,
    })
}

fn search_workspace_from_row(row: &Row, relevance_score: i32) -> Result<SearchResult, ApiError> {
    Ok(SearchResult {
        id: row_string(row, "id")?,
        result_type: "workspace".to_string(),
        title: row_string(row, "name")?,
        description: row_optional_string(row, "description")?,
        content: None,
        project_id: None,
        project_name: None,
        workspace_id: Some(row_string(row, "id")?),
        workspace_name: Some(row_string(row, "name")?),
        user_id: None,
        user_name: None,
        created_at: row_string(row, "created_at")?,
        relevance_score,
        task_number: None,
        project_slug: None,
        priority: None,
        status: None,
    })
}

fn to_display_case(value: &str) -> String {
    value
        .replace(['-', '_'], " ")
        .split_whitespace()
        .map(|part| {
            let mut chars = part.chars();
            let first = chars
                .next()
                .map(|character| character.to_uppercase().collect::<String>())
                .unwrap_or_default();
            format!("{first}{}", chars.as_str().to_lowercase())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn event_value_string(data: &serde_json::Map<String, Value>, key: &str, fallback: &str) -> String {
    data.get(key)
        .map(|value| match value {
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            _ => fallback.to_string(),
        })
        .unwrap_or_else(|| fallback.to_string())
}

fn activity_search_content(
    activity_type: &str,
    content: Option<String>,
    event_data: Option<String>,
) -> Option<String> {
    if content.as_ref().is_some_and(|value| !value.is_empty()) {
        return content;
    }
    let data = event_data
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|value| value.as_object().cloned());
    let Some(data) = data else {
        return None;
    };
    match activity_type {
        "status_changed" => Some(format!(
            "changed status from {} to {}",
            to_display_case(&event_value_string(&data, "oldStatus", "")),
            to_display_case(&event_value_string(&data, "newStatus", "")),
        )),
        "priority_changed" => Some(format!(
            "changed priority from {} to {}",
            to_display_case(&event_value_string(&data, "oldPriority", "")),
            to_display_case(&event_value_string(&data, "newPriority", "")),
        )),
        "unassigned" => Some("unassigned the task".to_string()),
        "assignee_changed" => {
            if data
                .get("isSelfAssigned")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                Some("assigned the task to themselves".to_string())
            } else {
                Some(format!(
                    "assigned the task to {}",
                    event_value_string(&data, "newAssignee", "someone")
                ))
            }
        }
        "due_date_changed" => {
            let new_due_date = event_value_string(&data, "newDueDate", "");
            let old_due_date = event_value_string(&data, "oldDueDate", "");
            if new_due_date.is_empty() {
                Some("cleared the due date".to_string())
            } else if old_due_date.is_empty() {
                Some(format!("set due date to {new_due_date}"))
            } else {
                Some(format!(
                    "changed due date from {old_due_date} to {new_due_date}"
                ))
            }
        }
        "title_changed" => Some(format!(
            "changed title from \"{}\" to \"{}\"",
            event_value_string(&data, "oldTitle", ""),
            event_value_string(&data, "newTitle", "")
        )),
        "task" => Some("created the task".to_string()),
        _ => None,
    }
}

fn parse_short_task_id(value: &str) -> Option<(String, i32)> {
    let (prefix, number) = value.rsplit_once('-')?;
    let first = prefix.chars().next()?;
    if !first.is_ascii_alphabetic()
        || !prefix.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
        || number.is_empty()
        || !number.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    Some((prefix.to_string(), number.parse().ok()?))
}

async fn global_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Value>, ApiError> {
    let search_query = query
        .q
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "Query must be at least 1 character",
            )
        })?;
    let result_type = query.result_type.as_deref().unwrap_or("all");
    if !matches!(
        result_type,
        "all" | "tasks" | "projects" | "workspaces" | "comments" | "activities"
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid search type",
        ));
    }
    let limit = query.limit.unwrap_or(20);
    if !(1..=50).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Limit must be between 1 and 50",
        ));
    }
    let workspace_id = query.workspace_id.ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Workspace ID could not be determined",
        )
    })?;
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;

    let pattern = format!("%{}%", search_query.to_lowercase());
    let project_filter = query.project_id.clone();
    let limit_i64 = limit as i64;
    let mut results = Vec::new();

    if matches!(result_type, "all" | "tasks") {
        let mut seen_task_ids = HashSet::new();
        if let Some((slug, task_number)) = parse_short_task_id(&search_query) {
            let rows = state
                .database
                .client
                .query(
                    r#"
                      SELECT t.id, t.title, t.description, t.project_id,
                             p.name AS project_name, p.slug AS project_slug,
                             p.workspace_id, w.name AS workspace_name,
                             t.assignee_id AS user_id, u.name AS user_name,
                             to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                             t.number AS task_number, t.priority, t.status
                      FROM task t
                      INNER JOIN project p ON p.id = t.project_id
                      LEFT JOIN workspace w ON w.id = p.workspace_id
                      LEFT JOIN "user" u ON u.id = t.assignee_id
                      WHERE p.workspace_id = $1
                        AND ($4::text IS NULL OR t.project_id = $4)
                        AND p.slug ILIKE $2
                        AND t.number = $3
                      LIMIT 1
                    "#,
                    &[&workspace_id, &slug, &task_number, &project_filter],
                )
                .await
                .map_err(database_error)?;
            for row in rows {
                let task = search_task_from_row(&row, 10)?;
                seen_task_ids.insert(task.id.clone());
                results.push(task);
            }
        }

        let rows = state
            .database
            .client
            .query(
                r#"
                  SELECT t.id, t.title, t.description, t.project_id,
                         p.name AS project_name, p.slug AS project_slug,
                         p.workspace_id, w.name AS workspace_name,
                         t.assignee_id AS user_id, u.name AS user_name,
                         to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                         t.number AS task_number, t.priority, t.status,
                         CASE
                           WHEN LOWER(t.title) LIKE $3 THEN 3
                           WHEN LOWER(t.description) LIKE $3 THEN 2
                           ELSE 1
                         END AS relevance_score
                  FROM task t
                  INNER JOIN project p ON p.id = t.project_id
                  LEFT JOIN workspace w ON w.id = p.workspace_id
                  LEFT JOIN "user" u ON u.id = t.assignee_id
                  WHERE p.workspace_id = $1
                    AND ($2::text IS NULL OR t.project_id = $2)
                    AND (t.title ILIKE $3 OR t.description ILIKE $3)
                  ORDER BY relevance_score DESC, t.created_at DESC
                  LIMIT $4
                "#,
                &[&workspace_id, &project_filter, &pattern, &limit_i64],
            )
            .await
            .map_err(database_error)?;
        for row in rows {
            let task_id = row_string(&row, "id")?;
            if seen_task_ids.contains(&task_id) {
                continue;
            }
            let relevance_score = row.try_get("relevance_score").map_err(database_error)?;
            results.push(search_task_from_row(&row, relevance_score)?);
        }
    }

    if matches!(result_type, "all" | "projects") {
        let rows = state
            .database
            .client
            .query(
                r#"
                  SELECT p.id, p.name, p.description, p.slug, p.workspace_id,
                         w.name AS workspace_name,
                         to_char(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                         CASE
                           WHEN LOWER(p.name) LIKE $2 THEN 3
                           WHEN LOWER(p.description) LIKE $2 THEN 2
                           ELSE 1
                         END AS relevance_score
                  FROM project p
                  LEFT JOIN workspace w ON w.id = p.workspace_id
                  WHERE p.workspace_id = $1
                    AND (p.name ILIKE $2 OR p.description ILIKE $2)
                  ORDER BY relevance_score DESC, p.created_at DESC
                  LIMIT $3
                "#,
                &[&workspace_id, &pattern, &limit_i64],
            )
            .await
            .map_err(database_error)?;
        for row in rows {
            let relevance_score = row.try_get("relevance_score").map_err(database_error)?;
            results.push(search_project_from_row(&row, relevance_score)?);
        }
    }

    if matches!(result_type, "all" | "workspaces") {
        let rows = state
            .database
            .client
            .query(
                r#"
                  SELECT id, name, description,
                         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                         CASE
                           WHEN LOWER(name) LIKE $2 THEN 3
                           WHEN LOWER(description) LIKE $2 THEN 2
                           ELSE 1
                         END AS relevance_score
                  FROM workspace
                  WHERE id = $1
                    AND (name ILIKE $2 OR description ILIKE $2)
                  ORDER BY relevance_score DESC, created_at DESC
                  LIMIT $3
                "#,
                &[&workspace_id, &pattern, &limit_i64],
            )
            .await
            .map_err(database_error)?;
        for row in rows {
            let relevance_score = row.try_get("relevance_score").map_err(database_error)?;
            results.push(search_workspace_from_row(&row, relevance_score)?);
        }
    }

    if matches!(result_type, "all" | "comments" | "activities") {
        let type_filter = if result_type == "comments" {
            "AND a.type = 'comment'"
        } else {
            ""
        };
        let sql = format!(
            r#"
              SELECT a.id, a.type, a.content, a.event_data::text AS event_data,
                     t.title AS task_title, t.number AS task_number,
                     p.id AS project_id, p.name AS project_name, p.slug AS project_slug,
                     p.workspace_id, w.name AS workspace_name,
                     a.user_id, u.name AS user_name,
                     to_char(a.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     CASE
                       WHEN LOWER(COALESCE(a.content, a.event_data::text, '')) LIKE $3 THEN 2
                       WHEN LOWER(t.title) LIKE $3 THEN 1
                       ELSE 1
                     END AS relevance_score
              FROM activity a
              INNER JOIN task t ON t.id = a.task_id
              INNER JOIN project p ON p.id = t.project_id
              LEFT JOIN workspace w ON w.id = p.workspace_id
              LEFT JOIN "user" u ON u.id = a.user_id
              WHERE p.workspace_id = $1
                AND ($2::text IS NULL OR t.project_id = $2)
                AND (
                  COALESCE(a.content, a.event_data::text, '') ILIKE $3
                  OR t.title ILIKE $3
                )
                {type_filter}
              ORDER BY relevance_score DESC, a.created_at DESC
              LIMIT $4
            "#,
        );
        let rows = state
            .database
            .client
            .query(
                &sql,
                &[&workspace_id, &project_filter, &pattern, &limit_i64],
            )
            .await
            .map_err(database_error)?;
        for row in rows {
            let activity_type = row_string(&row, "type")?;
            let is_comment = activity_type == "comment";
            let task_title = row_optional_string(&row, "task_title")?;
            let result = SearchResult {
                id: row_string(&row, "id")?,
                result_type: if is_comment {
                    "comment".to_string()
                } else {
                    "activity".to_string()
                },
                title: if is_comment {
                    format!("Comment on {}", task_title.as_deref().unwrap_or("task"))
                } else {
                    format!(
                        "{} on {}",
                        activity_type,
                        task_title.as_deref().unwrap_or("task")
                    )
                },
                description: None,
                content: activity_search_content(
                    &activity_type,
                    row_optional_string(&row, "content")?,
                    row_optional_string(&row, "event_data")?,
                ),
                project_id: row_optional_string(&row, "project_id")?,
                project_name: row_optional_string(&row, "project_name")?,
                workspace_id: row_optional_string(&row, "workspace_id")?,
                workspace_name: row_optional_string(&row, "workspace_name")?,
                user_id: row_optional_string(&row, "user_id")?,
                user_name: row_optional_string(&row, "user_name")?,
                created_at: row_string(&row, "created_at")?,
                relevance_score: row.try_get("relevance_score").map_err(database_error)?,
                task_number: row_optional_i32(&row, "task_number")?,
                project_slug: row_optional_string(&row, "project_slug")?,
                priority: None,
                status: None,
            };
            results.push(result);
        }
    }

    results.sort_by(|left, right| {
        right
            .relevance_score
            .cmp(&left.relevance_score)
            .then_with(|| right.created_at.cmp(&left.created_at))
    });
    let total_count = results.len();
    results.truncate(limit);

    Ok(Json(json!({
        "results": results,
        "totalCount": total_count,
        "searchQuery": search_query,
    })))
}

async fn workflow_rule_project(state: &AppState, rule_id: &str) -> Result<String, ApiError> {
    state
        .database
        .client
        .query_opt(
            "SELECT project_id FROM workflow_rule WHERE id = $1 LIMIT 1",
            &[&rule_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_string(&row, "project_id"))
        .transpose()?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Workflow rule not found"))
}

async fn workflow_rule_record(state: &AppState, rule_id: &str) -> Result<Value, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT id, project_id, integration_type, event_type, column_id,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM workflow_rule
              WHERE id = $1
              LIMIT 1
            "#,
            &[&rule_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Workflow rule not found"))?;
    Ok(json!({
        "id": row_string(&row, "id")?,
        "projectId": row_string(&row, "project_id")?,
        "integrationType": row_string(&row, "integration_type")?,
        "eventType": row_string(&row, "event_type")?,
        "columnId": row_string(&row, "column_id")?,
        "createdAt": row_string(&row, "created_at")?,
        "updatedAt": row_string(&row, "updated_at")?,
    }))
}

async fn list_workflow_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let _ = auth_for_project(&state, &headers, &project_id).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT r.id, r.project_id, r.integration_type, r.event_type, r.column_id,
                     c.name AS column_name, c.slug AS column_slug,
                     to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(r.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM workflow_rule r
              LEFT JOIN "column" c ON c.id = r.column_id
              WHERE r.project_id = $1
              ORDER BY r.created_at ASC
            "#,
            &[&project_id],
        )
        .await
        .map_err(database_error)?;
    rows.into_iter()
        .map(|row| {
            Ok(json!({
                "id": row_string(&row, "id")?,
                "projectId": row_string(&row, "project_id")?,
                "integrationType": row_string(&row, "integration_type")?,
                "eventType": row_string(&row, "event_type")?,
                "columnId": row_string(&row, "column_id")?,
                "columnName": row_optional_string(&row, "column_name")?,
                "columnSlug": row_optional_string(&row, "column_slug")?,
                "createdAt": row_string(&row, "created_at")?,
                "updatedAt": row_string(&row, "updated_at")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()
        .map(Json)
}

async fn upsert_workflow_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<WorkflowRuleInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "project", "update").await?;

    let column_exists = state
        .database
        .client
        .query_opt(
            "SELECT 1 FROM \"column\" WHERE id = $1 AND project_id = $2 LIMIT 1",
            &[&input.column_id, &project_id],
        )
        .await
        .map_err(database_error)?
        .is_some();
    if !column_exists {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Column does not belong to the provided project",
        ));
    }

    let existing = state
        .database
        .client
        .query_opt(
            r#"
              SELECT id FROM workflow_rule
              WHERE project_id = $1 AND integration_type = $2 AND event_type = $3
              LIMIT 1
            "#,
            &[&project_id, &input.integration_type, &input.event_type],
        )
        .await
        .map_err(database_error)?;
    let rule_id = if let Some(row) = existing {
        let rule_id = row_string(&row, "id")?;
        state
            .database
            .client
            .execute(
                "UPDATE workflow_rule SET column_id = $1, updated_at = NOW() WHERE id = $2",
                &[&input.column_id, &rule_id],
            )
            .await
            .map_err(database_error)?;
        rule_id
    } else {
        let rule_id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO workflow_rule
                    (id, project_id, integration_type, event_type, column_id, created_at, updated_at)
                  VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
                "#,
                &[
                    &rule_id,
                    &project_id,
                    &input.integration_type,
                    &input.event_type,
                    &input.column_id,
                ],
            )
            .await
            .map_err(database_error)?;
        rule_id
    };

    Ok(Json(workflow_rule_record(&state, &rule_id).await?))
}

async fn delete_workflow_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let project_id = workflow_rule_project(&state, &id).await?;
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "project", "update").await?;
    let existing = workflow_rule_record(&state, &id).await?;
    let deleted = state
        .database
        .client
        .execute("DELETE FROM workflow_rule WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?;
    if deleted == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Workflow rule not found",
        ));
    }
    Ok(Json(existing))
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
    let (auth, workspace_id) = auth_for_task(&state, &headers, &id).await?;
    let existing_task = task_by_id(&state.database, &id).await?;
    let project_id = existing_task.project_id.clone();
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
    if existing_task.status != task.status {
        if let Some(assignee_id) = task
            .user_id
            .as_deref()
            .filter(|user_id| *user_id != auth.user_id)
        {
            let event_data = json!({
                "taskTitle": task.title.clone(),
                "oldStatus": existing_task.status,
                "newStatus": task.status.clone(),
                "projectId": task.project_id.clone(),
                "workspaceId": workspace_id,
            });
            let _ = create_user_notification(
                &state,
                assignee_id,
                None,
                None,
                "task_status_changed",
                Some(&event_data),
                Some(&task.id),
                Some("task"),
            )
            .await?;
        }
    }
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

async fn update_task_assignee(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<AssigneeInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, workspace_id) = auth_for_task(&state, &headers, &id).await?;
    let existing_task = task_by_id(&state.database, &id).await?;
    if existing_task.user_id == input.user_id {
        return Ok(Json(existing_task));
    }
    if let Some(user_id) = input.user_id.as_deref() {
        let user_exists = state
            .database
            .client
            .query_opt("SELECT 1 FROM \"user\" WHERE id = $1 LIMIT 1", &[&user_id])
            .await
            .map_err(database_error)?
            .is_some();
        if !user_exists {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "User not found"));
        }
    }
    state
        .database
        .client
        .execute(
            "UPDATE task SET assignee_id = $1, updated_at = NOW() WHERE id = $2",
            &[&input.user_id, &id],
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
    if let Some(assignee_id) = task
        .user_id
        .as_deref()
        .filter(|user_id| *user_id != auth.user_id)
    {
        let event_data = json!({
            "taskTitle": task.title.clone(),
            "projectId": task.project_id.clone(),
            "workspaceId": workspace_id,
        });
        let _ = create_user_notification(
            &state,
            assignee_id,
            None,
            None,
            "task_assignee_changed",
            Some(&event_data),
            Some(&task.id),
            Some("task"),
        )
        .await?;
    }
    Ok(Json(task))
}

async fn update_task_description(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<DescriptionInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, _) = auth_for_task(&state, &headers, &id).await?;
    let updated = state
        .database
        .client
        .execute(
            "UPDATE task SET description = $1, updated_at = NOW() WHERE id = $2",
            &[&input.description, &id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Task not found"));
    }
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

async fn move_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<MoveTaskInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_task(&state, &headers, &id).await?;
    let existing_task = task_by_id(&state.database, &id).await?;
    if existing_task.project_id == input.destination_project_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Task is already in that project",
        ));
    }
    let destination_project = state
        .database
        .client
        .query_opt(
            "SELECT id, name, workspace_id FROM project WHERE id = $1 LIMIT 1",
            &[&input.destination_project_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Project not found"))?;
    let destination_workspace = row_string(&destination_project, "workspace_id")?;
    if destination_workspace != workspace_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Tasks can only be moved within the same workspace",
        ));
    }
    let source_project = state
        .database
        .client
        .query_one(
            "SELECT id, name FROM project WHERE id = $1 LIMIT 1",
            &[&existing_task.project_id],
        )
        .await
        .map_err(database_error)?;
    let columns = state
        .database
        .client
        .query(
            "SELECT id, slug FROM \"column\" WHERE project_id = $1 ORDER BY position ASC",
            &[&input.destination_project_id],
        )
        .await
        .map_err(database_error)?;
    let selected_column = if let Some(status) = input.destination_status.as_deref() {
        columns
            .iter()
            .find(|row| row.try_get::<_, String>("slug").ok().as_deref() == Some(status))
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Selected status is not valid for the destination project",
                )
            })?
    } else {
        columns
            .iter()
            .find(|row| {
                row.try_get::<_, String>("slug").ok().as_deref() == Some(&existing_task.status)
            })
            .or_else(|| columns.first())
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Destination project does not have a workflow",
                )
            })?
    };
    let destination_status = row_string(selected_column, "slug")?;
    let destination_column_id = row_string(selected_column, "id")?;
    let next_number: i32 = state
        .database
        .client
        .query_one(
            "UPDATE project SET last_task_number = last_task_number + 1 WHERE id = $1 RETURNING last_task_number",
            &[&input.destination_project_id],
        )
        .await
        .map_err(database_error)?
        .try_get("last_task_number")
        .map_err(database_error)?;
    let next_position: i32 = state
        .database
        .client
        .query_one(
            "SELECT COALESCE(MAX(position), 0) + 1 AS position FROM task WHERE project_id = $1 AND status = $2 AND column_id = $3",
            &[&input.destination_project_id, &destination_status, &destination_column_id],
        )
        .await
        .map_err(database_error)?
        .try_get("position")
        .map_err(database_error)?;
    state
        .database
        .client
        .execute(
            r#"
              UPDATE task
              SET project_id = $1, status = $2, column_id = $3, number = $4,
                  position = $5, updated_at = NOW()
              WHERE id = $6
            "#,
            &[
                &input.destination_project_id,
                &destination_status,
                &destination_column_id,
                &next_number,
                &next_position,
                &id,
            ],
        )
        .await
        .map_err(database_error)?;
    state
        .database
        .client
        .execute(
            "UPDATE asset SET project_id = $1 WHERE task_id = $2",
            &[&input.destination_project_id, &id],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &id).await?;
    publish_task_move(
        &state,
        existing_task.project_id.clone(),
        id.clone(),
        &auth,
        &headers,
    );
    publish_task_move(&state, task.project_id.clone(), id.clone(), &auth, &headers);
    Ok(Json(json!({
        "task": task,
        "sourceProjectId": row_string(&source_project, "id")?,
        "destinationProjectId": input.destination_project_id,
    })))
}

async fn export_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _ = auth_for_project(&state, &headers, &project_id).await?;
    let project = state
        .database
        .client
        .query_opt(
            "SELECT id, name, slug, description FROM project WHERE id = $1 LIMIT 1",
            &[&project_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Project not found"))?;
    let rows = state
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
    let exported_at: String = state
        .database
        .client
        .query_one(
            "SELECT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS exported_at",
            &[],
        )
        .await
        .map_err(database_error)?
        .try_get("exported_at")
        .map_err(database_error)?;
    let tasks = rows
        .into_iter()
        .map(|row| {
            Ok(json!({
                "title": row_string(&row, "title")?,
                "description": row_optional_string(&row, "description")?.unwrap_or_default(),
                "status": row_string(&row, "status")?,
                "priority": row_optional_string(&row, "priority")?.unwrap_or_else(|| "low".to_string()),
                "dueDate": row_optional_string(&row, "due_date")?,
                "startDate": row_optional_string(&row, "start_date")?,
                "userId": row_optional_string(&row, "user_id")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(json!({
        "project": {
            "name": row_string(&project, "name")?,
            "slug": row_string(&project, "slug")?,
            "description": row_optional_string(&project, "description")?,
            "exportedAt": exported_at,
        },
        "tasks": tasks,
    })))
}

struct BulkTaskRecord {
    id: String,
    project_id: String,
    workspace_id: String,
}

async fn bulk_update_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BulkTaskInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    if input.task_ids.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "At least one task ID is required",
        ));
    }
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT t.id, t.title, t.project_id, t.assignee_id AS user_id,
                     to_char(t.due_date AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS due_date,
                     p.workspace_id
              FROM task t
              INNER JOIN project p ON p.id = t.project_id
              WHERE t.id = ANY($1::text[])
            "#,
            &[&input.task_ids],
        )
        .await
        .map_err(database_error)?;
    if rows.is_empty() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "No tasks found"));
    }
    let tasks = rows
        .iter()
        .map(|row| {
            Ok(BulkTaskRecord {
                id: row_string(row, "id")?,
                project_id: row_string(row, "project_id")?,
                workspace_id: row_string(row, "workspace_id")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let workspace_ids = tasks
        .iter()
        .map(|task| task.workspace_id.clone())
        .collect::<HashSet<_>>();
    if workspace_ids.len() > 1 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "All tasks must belong to the same workspace",
        ));
    }
    let workspace_id = workspace_ids
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Could not determine workspace"))?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let found_ids = tasks.iter().map(|task| task.id.clone()).collect::<Vec<_>>();
    let mut updated_count: i64 = 0;

    match input.operation.as_str() {
        "updateStatus" => {
            let status = input
                .value
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiError::new(StatusCode::BAD_REQUEST, "Status value is required")
                })?;
            let project_ids = tasks
                .iter()
                .map(|task| task.project_id.clone())
                .collect::<HashSet<_>>();
            for project_id in project_ids {
                let column_id = if matches!(status, "planned" | "archived") {
                    None
                } else {
                    state
                        .database
                        .client
                        .query_opt(
                            "SELECT id FROM \"column\" WHERE project_id = $1 AND slug = $2 LIMIT 1",
                            &[&project_id, &status],
                        )
                        .await
                        .map_err(database_error)?
                        .map(|row| row_string(&row, "id"))
                        .transpose()?
                        .ok_or_else(|| {
                            ApiError::new(
                                StatusCode::BAD_REQUEST,
                                format!("Invalid status \"{status}\" for this project"),
                            )
                        })?
                        .into()
                };
                let project_task_ids = tasks
                    .iter()
                    .filter(|task| task.project_id == project_id)
                    .map(|task| task.id.clone())
                    .collect::<Vec<_>>();
                updated_count += state
                    .database
                    .client
                    .execute(
                        "UPDATE task SET status = $1, column_id = $2, updated_at = NOW() WHERE id = ANY($3::text[])",
                        &[&status, &column_id, &project_task_ids],
                    )
                    .await
                    .map_err(database_error)? as i64;
                for task_id in project_task_ids {
                    publish_task_event(
                        &state,
                        "TASK_UPDATED",
                        project_id.clone(),
                        task_id,
                        &auth,
                        &headers,
                    );
                }
            }
        }
        "updatePriority" => {
            let priority = input
                .value
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiError::new(StatusCode::BAD_REQUEST, "Priority value is required")
                })?;
            validate_priority(priority)?;
            updated_count = state
                .database
                .client
                .execute(
                    "UPDATE task SET priority = $1, updated_at = NOW() WHERE id = ANY($2::text[])",
                    &[&priority, &found_ids],
                )
                .await
                .map_err(database_error)? as i64;
            for task in &tasks {
                publish_task_event(
                    &state,
                    "TASK_UPDATED",
                    task.project_id.clone(),
                    task.id.clone(),
                    &auth,
                    &headers,
                );
            }
        }
        "updateAssignee" => {
            let assignee_id = input
                .value
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            if let Some(user_id) = assignee_id.as_deref() {
                let user_exists = state
                    .database
                    .client
                    .query_opt("SELECT 1 FROM \"user\" WHERE id = $1 LIMIT 1", &[&user_id])
                    .await
                    .map_err(database_error)?
                    .is_some();
                if !user_exists {
                    return Err(ApiError::new(StatusCode::BAD_REQUEST, "User not found"));
                }
            }
            updated_count = state
                .database
                .client
                .execute(
                    "UPDATE task SET assignee_id = $1, updated_at = NOW() WHERE id = ANY($2::text[])",
                    &[&assignee_id, &found_ids],
                )
                .await
                .map_err(database_error)? as i64;
            for task in &tasks {
                publish_task_event(
                    &state,
                    "TASK_UPDATED",
                    task.project_id.clone(),
                    task.id.clone(),
                    &auth,
                    &headers,
                );
            }
        }
        "delete" => {
            updated_count = state
                .database
                .client
                .execute("DELETE FROM task WHERE id = ANY($1::text[])", &[&found_ids])
                .await
                .map_err(database_error)? as i64;
            for task in &tasks {
                publish_task_event(
                    &state,
                    "TASK_DELETED",
                    task.project_id.clone(),
                    task.id.clone(),
                    &auth,
                    &headers,
                );
            }
        }
        "addLabel" => {
            let label_id = input
                .value
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Label ID is required"))?;
            let label = state
                .database
                .client
                .query_opt(
                    "SELECT name, color FROM label WHERE id = $1 LIMIT 1",
                    &[&label_id],
                )
                .await
                .map_err(database_error)?
                .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Label not found"))?;
            let label_name = row_string(&label, "name")?;
            let label_color = row_string(&label, "color")?;
            for task in &tasks {
                let inserted = state
                    .database
                    .client
                    .execute(
                        "INSERT INTO label (id, name, color, created_at, updated_at, task_id, workspace_id) VALUES ($1, $2, $3, NOW(), NOW(), $4, $5) ON CONFLICT DO NOTHING",
                        &[
                            &Uuid::new_v4().to_string(),
                            &label_name,
                            &label_color,
                            &task.id,
                            &workspace_id,
                        ],
                    )
                    .await
                    .map_err(database_error)?;
                updated_count += inserted as i64;
                if inserted > 0 {
                    publish_task_event(
                        &state,
                        "TASK_LABEL_UPDATED",
                        task.project_id.clone(),
                        task.id.clone(),
                        &auth,
                        &headers,
                    );
                }
            }
        }
        "removeLabel" => {
            let label_id = input
                .value
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Label ID is required"))?;
            updated_count = state
                .database
                .client
                .execute(
                    "UPDATE label SET task_id = NULL, updated_at = NOW() WHERE id = $1 AND task_id = ANY($2::text[])",
                    &[&label_id, &found_ids],
                )
                .await
                .map_err(database_error)? as i64;
            for task in &tasks {
                publish_task_event(
                    &state,
                    "TASK_LABEL_UPDATED",
                    task.project_id.clone(),
                    task.id.clone(),
                    &auth,
                    &headers,
                );
            }
        }
        "updateDueDate" => {
            let due_date = input.value.clone().filter(|value| !value.is_empty());
            if let Some(value) = due_date.as_deref() {
                state
                    .database
                    .client
                    .query_one("SELECT $1::text::timestamptz", &[&value])
                    .await
                    .map_err(|error| {
                        ApiError::new(
                            StatusCode::BAD_REQUEST,
                            format!("Invalid date value \"{value}\": {error}"),
                        )
                    })?;
            }
            updated_count = state
                .database
                .client
                .execute(
                    "UPDATE task SET due_date = $1::text::timestamptz AT TIME ZONE 'UTC', updated_at = NOW() WHERE id = ANY($2::text[])",
                    &[&due_date, &found_ids],
                )
                .await
                .map_err(database_error)? as i64;
            for task in &tasks {
                publish_task_event(
                    &state,
                    "TASK_UPDATED",
                    task.project_id.clone(),
                    task.id.clone(),
                    &auth,
                    &headers,
                );
            }
        }
        operation => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("Unknown operation \"{operation}\""),
            ));
        }
    }

    Ok(Json(json!({
        "success": true,
        "updatedCount": updated_count,
    })))
}

async fn import_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<ImportTasksInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    let project = state
        .database
        .client
        .query_opt(
            "SELECT id, name, slug FROM project WHERE id = $1 LIMIT 1",
            &[&project_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Project not found"))?;
    let valid_statuses = state
        .database
        .client
        .query(
            "SELECT slug FROM \"column\" WHERE project_id = $1 ORDER BY position ASC",
            &[&project_id],
        )
        .await
        .map_err(database_error)?
        .into_iter()
        .map(|row| row_string(&row, "slug"))
        .collect::<Result<HashSet<_>, ApiError>>()?;
    let mut valid_statuses = valid_statuses;
    valid_statuses.insert("planned".to_string());
    valid_statuses.insert("archived".to_string());

    let task_count = input.tasks.len() as i32;
    let mut next_number = if task_count == 0 {
        0
    } else {
        let last_number: i32 = state
            .database
            .client
            .query_one(
                "UPDATE project SET last_task_number = last_task_number + $1 WHERE id = $2 RETURNING last_task_number",
                &[&task_count, &project_id],
            )
            .await
            .map_err(database_error)?
            .try_get("last_task_number")
            .map_err(database_error)?;
        last_number - task_count
    };
    let imported_at: String = state
        .database
        .client
        .query_one(
            "SELECT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS imported_at",
            &[],
        )
        .await
        .map_err(database_error)?
        .try_get("imported_at")
        .map_err(database_error)?;
    let mut results = Vec::with_capacity(input.tasks.len());

    for task_input in input.tasks {
        let (status, status_warning) = if valid_statuses.contains(&task_input.status) {
            (task_input.status.clone(), None)
        } else {
            (
                "planned".to_string(),
                Some(format!(
                    "Unknown status \"{}\" mapped to \"planned\"",
                    task_input.status
                )),
            )
        };
        let (priority, priority_warning) = match task_input.priority.as_deref() {
            Some(value)
                if matches!(value, "no-priority" | "low" | "medium" | "high" | "urgent") =>
            {
                (value.to_string(), None)
            }
            Some(value) => (
                "no-priority".to_string(),
                Some(format!(
                    "Unknown priority \"{value}\" mapped to \"no-priority\""
                )),
            ),
            None => ("low".to_string(), None),
        };
        let column_id = if matches!(status.as_str(), "planned" | "archived") {
            None
        } else {
            state
                .database
                .client
                .query_opt(
                    "SELECT id FROM \"column\" WHERE project_id = $1 AND slug = $2 LIMIT 1",
                    &[&project_id, &status],
                )
                .await
                .map_err(database_error)?
                .map(|row| row_string(&row, "id"))
                .transpose()?
        };
        next_number += 1;
        let id = Uuid::new_v4().to_string();
        let description = task_input.description.clone().unwrap_or_default();
        let assignee_id = task_input.user_id.clone().filter(|value| !value.is_empty());
        let insert_result = state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO task
                    (id, project_id, number, assignee_id, title, description,
                     status, column_id, priority, start_date, due_date, created_at, updated_at)
                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                          $10::text::timestamptz AT TIME ZONE 'UTC',
                          $11::text::timestamptz AT TIME ZONE 'UTC', NOW(), NOW())
                "#,
                &[
                    &id,
                    &project_id,
                    &next_number,
                    &assignee_id,
                    &task_input.title,
                    &description,
                    &status,
                    &column_id,
                    &priority,
                    &task_input.start_date,
                    &task_input.due_date,
                ],
            )
            .await;
        match insert_result {
            Ok(_) => {
                let task = task_by_id(&state.database, &id).await?;
                publish_task_event(
                    &state,
                    "TASK_CREATED",
                    task.project_id.clone(),
                    task.id.clone(),
                    &auth,
                    &headers,
                );
                let warnings = [status_warning, priority_warning]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                let mut result = json!({
                    "success": true,
                    "task": task,
                });
                if !warnings.is_empty() {
                    result["warnings"] = json!(warnings);
                }
                results.push(result);
            }
            Err(error) => {
                results.push(json!({
                    "success": false,
                    "error": error.to_string(),
                    "task": {
                        "title": task_input.title,
                        "description": description,
                        "status": task_input.status,
                        "priority": task_input.priority.unwrap_or_else(|| "low".to_string()),
                        "startDate": task_input.start_date,
                        "dueDate": task_input.due_date,
                        "userId": task_input.user_id,
                    },
                }));
            }
        }
    }

    Ok(Json(json!({
        "importedAt": imported_at,
        "project": {
            "id": row_string(&project, "id")?,
            "name": row_string(&project, "name")?,
            "slug": row_string(&project, "slug")?,
        },
        "results": {
            "total": results.len(),
            "successful": results.iter().filter(|result| result["success"] == true).count(),
            "failed": results.iter().filter(|result| result["success"] == false).count(),
            "tasks": results,
        },
        "workspaceId": workspace_id,
    })))
}

async fn create_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<CreateTaskInput>,
) -> Result<Json<ApiTask>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
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
    if let Some(assignee_id) = input
        .user_id
        .as_deref()
        .filter(|user_id| *user_id != auth.user_id)
    {
        let event_data = json!({
            "taskTitle": task.title.clone(),
            "projectId": task.project_id.clone(),
            "workspaceId": workspace_id.clone(),
        });
        let _ = create_user_notification(
            &state,
            assignee_id,
            None,
            None,
            "task_created",
            Some(&event_data),
            Some(&task.id),
            Some("task"),
        )
        .await?;
    }
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

async fn get_oauth_id_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let id_token = state
        .database
        .client
        .query_opt(
            "SELECT id_token FROM account WHERE user_id = $1 AND provider_id = 'custom' LIMIT 1",
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?
        .and_then(|row| row_optional_string(&row, "id_token").ok().flatten());
    Ok(Json(json!({ "idToken": id_token })))
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

const ACTIVITY_SELECT_SQL: &str = r#"
    SELECT
      a.id,
      a.task_id,
      a.type,
      to_char(a.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
      to_char(a.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
      a.user_id,
      a.content,
      a.event_data::text AS event_data,
      a.external_user_name,
      a.external_user_avatar,
      a.external_source,
      a.external_url
    FROM activity a
"#;

fn activity_from_row(row: &Row) -> Result<ActivityRecord, ApiError> {
    let event_data = row_optional_string(row, "event_data")?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    Ok(ActivityRecord {
        id: row_string(row, "id")?,
        task_id: row_string(row, "task_id")?,
        activity_type: row_string(row, "type")?,
        created_at: row_string(row, "created_at")?,
        updated_at: row_string(row, "updated_at")?,
        user_id: row_optional_string(row, "user_id")?,
        content: row_optional_string(row, "content")?,
        event_data,
        external_user_name: row_optional_string(row, "external_user_name")?,
        external_user_avatar: row_optional_string(row, "external_user_avatar")?,
        external_source: row_optional_string(row, "external_source")?,
        external_url: row_optional_string(row, "external_url")?,
    })
}

fn normalize_activity_content(content: Option<String>) -> Option<String> {
    content.map(|content| {
        let mut normalized = String::with_capacity(content.len());
        let mut previous_was_newline = false;
        for character in content.chars() {
            if character == '\n' {
                if previous_was_newline {
                    continue;
                }
                previous_was_newline = true;
            } else {
                previous_was_newline = false;
            }
            normalized.push(character);
        }
        normalized
    })
}

async fn activity_by_id(state: &AppState, activity_id: &str) -> Result<ActivityRecord, ApiError> {
    let sql = format!("{ACTIVITY_SELECT_SQL} WHERE a.id = $1 LIMIT 1");
    let row = state
        .database
        .client
        .query_opt(&sql, &[&activity_id])
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Activity not found"))?;
    activity_from_row(&row)
}

async fn insert_activity(
    state: &AppState,
    task_id: &str,
    activity_type: &str,
    user_id: Option<&str>,
    content: Option<&str>,
    event_data: Option<&Value>,
) -> Result<ActivityRecord, ApiError> {
    let id = Uuid::new_v4().to_string();
    let user_id = user_id.unwrap_or_default().to_owned();
    let content = content.unwrap_or_default().to_owned();
    let event_data = event_data
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.to_string()))?
        .unwrap_or_default();
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO activity
                (id, task_id, type, user_id, content, event_data, created_at, updated_at)
              VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, '')::jsonb, NOW(), NOW())
            "#,
            &[
                &id,
                &task_id,
                &activity_type,
                &user_id,
                &content,
                &event_data,
            ],
        )
        .await
        .map_err(database_error)?;
    activity_by_id(state, &id).await
}

async fn list_activities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Result<Json<Vec<ActivityRecord>>, ApiError> {
    let _ = auth_for_task(&state, &headers, &task_id).await?;
    let sql = format!("{ACTIVITY_SELECT_SQL} WHERE a.task_id = $1 ORDER BY a.created_at DESC");
    let rows = state
        .database
        .client
        .query(&sql, &[&task_id])
        .await
        .map_err(database_error)?;
    let activities = rows
        .iter()
        .map(activity_from_row)
        .map(|activity| {
            activity.map(|mut activity| {
                activity.content = normalize_activity_content(activity.content);
                activity
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(activities))
}

async fn create_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateActivityInput>,
) -> Result<Json<ActivityRecord>, ApiError> {
    let _ = auth_for_task(&state, &headers, &input.task_id).await?;
    let activity = insert_activity(
        &state,
        &input.task_id,
        &input.activity_type,
        Some(&input.user_id),
        input.message.as_deref(),
        input.event_data.as_ref(),
    )
    .await?;
    let task = task_by_id(&state.database, &input.task_id).await?;
    let auth = authenticate(&state, &headers).await?;
    publish_task_event(
        &state,
        "TASK_UPDATED",
        task.project_id,
        input.task_id,
        &auth,
        &headers,
    );
    Ok(Json(activity))
}

async fn create_activity_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ActivityCommentInput>,
) -> Result<Json<ActivityRecord>, ApiError> {
    let (auth, _) = auth_for_task(&state, &headers, &input.task_id).await?;
    let activity = insert_activity(
        &state,
        &input.task_id,
        "comment",
        Some(&auth.user_id),
        Some(&input.comment),
        None,
    )
    .await?;
    let task = task_by_id(&state.database, &input.task_id).await?;
    publish_task_event(
        &state,
        "COMMENT_UPDATED",
        task.project_id,
        input.task_id,
        &auth,
        &headers,
    );
    Ok(Json(activity))
}

async fn comment_identity(
    state: &AppState,
    activity_id: &str,
) -> Result<(String, String), ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            "SELECT task_id, user_id, type FROM activity WHERE id = $1 LIMIT 1",
            &[&activity_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "Comment not found or you are not the author",
            )
        })?;
    let activity_type = row_string(&row, "type")?;
    let user_id = row_optional_string(&row, "user_id")?;
    if activity_type != "comment" || user_id.is_none() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Comment not found or you are not the author",
        ));
    }
    Ok((row_string(&row, "task_id")?, user_id.unwrap_or_default()))
}

async fn update_comment_by_id(
    state: &AppState,
    headers: &HeaderMap,
    activity_id: &str,
    content: &str,
) -> Result<ActivityRecord, ApiError> {
    let (task_id, author_id) = comment_identity(state, activity_id).await?;
    let (auth, _) = auth_for_task(state, headers, &task_id).await?;
    if auth.user_id != author_id && !auth.is_admin() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Comment not found or you are not the author",
        ));
    }
    let updated = state
        .database
        .client
        .execute(
            "UPDATE activity SET content = $1, updated_at = NOW() WHERE id = $2 AND type = 'comment'",
            &[&content, &activity_id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Comment not found or you are not the author",
        ));
    }
    let task = task_by_id(&state.database, &task_id).await?;
    let activity = activity_by_id(state, activity_id).await?;
    publish_task_event(
        state,
        "COMMENT_UPDATED",
        task.project_id,
        task_id,
        &auth,
        headers,
    );
    Ok(activity)
}

async fn delete_comment_by_id(
    state: &AppState,
    headers: &HeaderMap,
    activity_id: &str,
) -> Result<ActivityRecord, ApiError> {
    let (task_id, author_id) = comment_identity(state, activity_id).await?;
    let (auth, _) = auth_for_task(state, headers, &task_id).await?;
    if auth.user_id != author_id && !auth.is_admin() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Comment not found or you are not the author",
        ));
    }
    let row = state
        .database
        .client
        .query_opt(
            &format!("{ACTIVITY_SELECT_SQL} WHERE a.id = $1 LIMIT 1"),
            &[&activity_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Comment not found"))?;
    let deleted = activity_from_row(&row)?;
    let count = state
        .database
        .client
        .execute(
            "DELETE FROM activity WHERE id = $1 AND type = 'comment'",
            &[&activity_id],
        )
        .await
        .map_err(database_error)?;
    if count == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Comment not found"));
    }
    let task = task_by_id(&state.database, &task_id).await?;
    publish_task_event(
        state,
        "COMMENT_UPDATED",
        task.project_id,
        task_id,
        &auth,
        headers,
    );
    Ok(deleted)
}

async fn list_comments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Result<Json<Vec<CommentRecord>>, ApiError> {
    let _ = auth_for_task(&state, &headers, &task_id).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT a.id, a.task_id, a.user_id, a.content,
                     to_char(a.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(a.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
                     u.name AS user_name, u.image AS user_image
              FROM activity a
              INNER JOIN "user" u ON u.id = a.user_id
              WHERE a.task_id = $1
                AND a.type = 'comment'
                AND a.user_id IS NOT NULL
                AND a.content IS NOT NULL
              ORDER BY a.created_at ASC
            "#,
            &[&task_id],
        )
        .await
        .map_err(database_error)?;
    let comments = rows
        .iter()
        .map(|row| {
            Ok(CommentRecord {
                id: row_string(row, "id")?,
                task_id: row_string(row, "task_id")?,
                user_id: row_string(row, "user_id")?,
                content: row_string(row, "content")?,
                created_at: row_string(row, "created_at")?,
                updated_at: row_string(row, "updated_at")?,
                user: CommentUser {
                    name: row_optional_string(row, "user_name")?,
                    image: row_optional_string(row, "user_image")?,
                },
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(comments))
}

async fn create_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    Json(input): Json<CommentContentInput>,
) -> Result<Json<ActivityRecord>, ApiError> {
    let (auth, workspace_id) = auth_for_task(&state, &headers, &task_id).await?;
    let activity = insert_activity(
        &state,
        &task_id,
        "comment",
        Some(&auth.user_id),
        Some(&input.content),
        None,
    )
    .await?;
    let task = task_by_id(&state.database, &task_id).await?;
    publish_task_event(
        &state,
        "COMMENT_UPDATED",
        task.project_id.clone(),
        task_id.clone(),
        &auth,
        &headers,
    );
    if let Some(assignee_id) = task
        .user_id
        .as_deref()
        .filter(|user_id| *user_id != auth.user_id)
    {
        let commenter_name = state
            .database
            .client
            .query_opt(
                "SELECT name FROM \"user\" WHERE id = $1 LIMIT 1",
                &[&auth.user_id],
            )
            .await
            .map_err(database_error)?
            .and_then(|row| row.try_get::<_, String>("name").ok());
        let comment_preview = input.content.chars().take(160).collect::<String>();
        let event_data = json!({
            "taskTitle": task.title.clone(),
            "commenterName": commenter_name,
            "commentPreview": comment_preview,
            "projectId": task.project_id.clone(),
            "workspaceId": workspace_id,
        });
        let _ = create_user_notification(
            &state,
            assignee_id,
            None,
            None,
            "task_comment",
            Some(&event_data),
            Some(&task.id),
            Some("task"),
        )
        .await?;
    }
    Ok(Json(activity))
}

async fn update_activity_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ActivityUpdateCommentInput>,
) -> Result<Json<ActivityRecord>, ApiError> {
    Ok(Json(
        update_comment_by_id(&state, &headers, &input.activity_id, &input.comment).await?,
    ))
}

async fn delete_activity_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ActivityDeleteCommentInput>,
) -> Result<Json<ActivityRecord>, ApiError> {
    Ok(Json(
        delete_comment_by_id(&state, &headers, &input.activity_id).await?,
    ))
}

async fn update_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(activity_id): Path<String>,
    Json(input): Json<CommentContentInput>,
) -> Result<Json<ActivityRecord>, ApiError> {
    Ok(Json(
        update_comment_by_id(&state, &headers, &activity_id, &input.content).await?,
    ))
}

async fn delete_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(activity_id): Path<String>,
) -> Result<Json<ActivityRecord>, ApiError> {
    Ok(Json(
        delete_comment_by_id(&state, &headers, &activity_id).await?,
    ))
}

fn relation_from_row(row: &Row) -> Result<TaskRelationRecord, ApiError> {
    Ok(TaskRelationRecord {
        id: row_string(row, "id")?,
        source_task_id: row_string(row, "source_task_id")?,
        target_task_id: row_string(row, "target_task_id")?,
        relation_type: row_string(row, "relation_type")?,
        created_at: row_string(row, "created_at")?,
    })
}

async fn relation_task(
    state: &AppState,
    task_id: &str,
    workspace_id: &str,
) -> Result<Option<RelationTask>, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT t.id, t.title, t.status, t.priority, t.number,
                     t.project_id, t.assignee_id AS user_id, u.name AS assignee_name
              FROM task t
              INNER JOIN project p ON p.id = t.project_id
              LEFT JOIN "user" u ON u.id = t.assignee_id
              WHERE t.id = $1 AND p.workspace_id = $2
              LIMIT 1
            "#,
            &[&task_id, &workspace_id],
        )
        .await
        .map_err(database_error)?;
    row.map(|row| {
        Ok(RelationTask {
            id: row_string(&row, "id")?,
            title: row_string(&row, "title")?,
            status: row_string(&row, "status")?,
            priority: row_optional_string(&row, "priority")?,
            number: row_optional_i32(&row, "number")?,
            project_id: row_string(&row, "project_id")?,
            user_id: row_optional_string(&row, "user_id")?,
            assignee_name: row_optional_string(&row, "assignee_name")?,
        })
    })
    .transpose()
}

async fn list_task_relations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Result<Json<Vec<TaskRelationWithTasks>>, ApiError> {
    let (_, workspace_id) = auth_for_task(&state, &headers, &task_id).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT id, source_task_id, target_task_id, relation_type,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
              FROM task_relation
              WHERE source_task_id = $1 OR target_task_id = $1
              ORDER BY created_at ASC
            "#,
            &[&task_id],
        )
        .await
        .map_err(database_error)?;
    let relations = rows
        .iter()
        .map(relation_from_row)
        .collect::<Result<Vec<_>, ApiError>>()?;
    let mut task_cache = HashMap::new();
    for relation in &relations {
        for related_task_id in [&relation.source_task_id, &relation.target_task_id] {
            if !task_cache.contains_key(related_task_id) {
                if let Some(task) = relation_task(&state, related_task_id, &workspace_id).await? {
                    task_cache.insert(related_task_id.clone(), task);
                }
            }
        }
    }
    let relations = relations
        .into_iter()
        .filter_map(|relation| {
            let source_task = task_cache.get(&relation.source_task_id)?.clone();
            let target_task = task_cache.get(&relation.target_task_id)?.clone();
            Some(TaskRelationWithTasks {
                id: relation.id,
                source_task_id: relation.source_task_id,
                target_task_id: relation.target_task_id,
                relation_type: relation.relation_type,
                created_at: relation.created_at,
                source_task,
                target_task,
            })
        })
        .collect();
    Ok(Json(relations))
}

fn validate_relation_type(relation_type: &str) -> Result<(), ApiError> {
    if matches!(relation_type, "subtask" | "blocks" | "related") {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid task relation type",
        ))
    }
}

async fn create_task_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TaskRelationInput>,
) -> Result<Json<TaskRelationRecord>, ApiError> {
    validate_relation_type(&input.relation_type)?;
    if input.source_task_id == input.target_task_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Cannot create a relation between a task and itself",
        ));
    }
    let (auth, workspace_id) = auth_for_task(&state, &headers, &input.source_task_id).await?;
    let target_workspace = task_workspace(&state.database, &input.target_task_id).await?;
    if target_workspace != workspace_id {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Target task not found",
        ));
    }
    let existing = state
        .database
        .client
        .query_opt(
            r#"
              SELECT id
              FROM task_relation
              WHERE relation_type = $1
                AND ((source_task_id = $2 AND target_task_id = $3)
                  OR (source_task_id = $3 AND target_task_id = $2))
              LIMIT 1
            "#,
            &[
                &input.relation_type,
                &input.source_task_id,
                &input.target_task_id,
            ],
        )
        .await
        .map_err(database_error)?;
    if existing.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "This relation already exists",
        ));
    }
    let id = Uuid::new_v4().to_string();
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO task_relation
                (id, source_task_id, target_task_id, relation_type, created_at)
              VALUES ($1, $2, $3, $4, NOW())
            "#,
            &[
                &id,
                &input.source_task_id,
                &input.target_task_id,
                &input.relation_type,
            ],
        )
        .await
        .map_err(database_error)?;
    let row = state
        .database
        .client
        .query_one(
            r#"
              SELECT id, source_task_id, target_task_id, relation_type,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
              FROM task_relation WHERE id = $1
            "#,
            &[&id],
        )
        .await
        .map_err(database_error)?;
    let relation = relation_from_row(&row)?;
    let source_task = task_by_id(&state.database, &input.source_task_id).await?;
    publish_relation_event(
        &state,
        "TASK_RELATION_UPDATED",
        source_task.project_id,
        input.source_task_id,
        input.target_task_id,
        &auth,
        &headers,
    );
    Ok(Json(relation))
}

async fn delete_task_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TaskRelationRecord>, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT id, source_task_id, target_task_id, relation_type,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
              FROM task_relation WHERE id = $1 LIMIT 1
            "#,
            &[&id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Task relation not found"))?;
    let relation = relation_from_row(&row)?;
    let (auth, _) = auth_for_task(&state, &headers, &relation.source_task_id).await?;
    let deleted = state
        .database
        .client
        .execute("DELETE FROM task_relation WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?;
    if deleted == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Task relation not found",
        ));
    }
    let source_task = task_by_id(&state.database, &relation.source_task_id).await?;
    publish_relation_event(
        &state,
        "TASK_RELATION_UPDATED",
        source_task.project_id,
        relation.source_task_id.clone(),
        relation.target_task_id.clone(),
        &auth,
        &headers,
    );
    Ok(Json(relation))
}

const TIME_ENTRY_SELECT_SQL: &str = r#"
    SELECT
      te.id,
      te.task_id,
      te.user_id,
      te.description,
      to_char(te.start_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS start_time,
      CASE
        WHEN te.end_time IS NULL THEN NULL
        ELSE to_char(te.end_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
      END AS end_time,
      te.duration,
      to_char(te.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
      to_char(te.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
      u.name AS user_name
    FROM time_entry te
    LEFT JOIN "user" u ON u.id = te.user_id
"#;

fn time_entry_from_row(row: &Row) -> Result<TimeEntryRecord, ApiError> {
    Ok(TimeEntryRecord {
        id: row_string(row, "id")?,
        task_id: row_string(row, "task_id")?,
        user_id: row_optional_string(row, "user_id")?,
        description: row_optional_string(row, "description")?,
        start_time: row_string(row, "start_time")?,
        end_time: row_optional_string(row, "end_time")?,
        duration: row_optional_i32(row, "duration")?,
        created_at: row_string(row, "created_at")?,
        updated_at: row_string(row, "updated_at")?,
        user_name: row_optional_string(row, "user_name")?,
    })
}

async fn time_entry_context(
    state: &AppState,
    time_entry_id: &str,
) -> Result<(String, String), ApiError> {
    state
        .database
        .client
        .query_opt(
            r#"
              SELECT te.task_id, p.workspace_id
              FROM time_entry te
              INNER JOIN task t ON t.id = te.task_id
              INNER JOIN project p ON p.id = t.project_id
              WHERE te.id = $1
              LIMIT 1
            "#,
            &[&time_entry_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| {
            Ok((
                row_string(&row, "task_id")?,
                row_string(&row, "workspace_id")?,
            ))
        })
        .transpose()?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Time entry not found"))
}

async fn time_entry_by_id(
    state: &AppState,
    time_entry_id: &str,
) -> Result<TimeEntryRecord, ApiError> {
    let sql = format!("{TIME_ENTRY_SELECT_SQL} WHERE te.id = $1 LIMIT 1");
    let row = state
        .database
        .client
        .query_opt(&sql, &[&time_entry_id])
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Time entry not found"))?;
    time_entry_from_row(&row)
}

async fn list_time_entries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Result<Json<Vec<TimeEntryRecord>>, ApiError> {
    let _ = auth_for_task(&state, &headers, &task_id).await?;
    let sql = format!("{TIME_ENTRY_SELECT_SQL} WHERE te.task_id = $1 ORDER BY te.start_time ASC");
    let rows = state
        .database
        .client
        .query(&sql, &[&task_id])
        .await
        .map_err(database_error)?;
    let entries = rows
        .iter()
        .map(time_entry_from_row)
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(entries))
}

async fn get_time_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TimeEntryRecord>, ApiError> {
    let (task_id, workspace_id) = time_entry_context(&state, &id).await?;
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let _ = task_id;
    Ok(Json(time_entry_by_id(&state, &id).await?))
}

async fn create_time_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateTimeEntryInput>,
) -> Result<Json<TimeEntryRecord>, ApiError> {
    let (auth, _) = auth_for_task(&state, &headers, &input.task_id).await?;
    let id = Uuid::new_v4().to_string();
    let end_time = input.end_time.unwrap_or_default();
    let description = input.description.unwrap_or_default();
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO time_entry
                (id, task_id, user_id, description, start_time, end_time, duration, created_at, updated_at)
              VALUES (
                $1,
                $2,
                $3,
                $4,
                $5::text::timestamptz AT TIME ZONE 'UTC',
                NULLIF($6, '')::text::timestamptz AT TIME ZONE 'UTC',
                CASE
                  WHEN NULLIF($6, '') IS NULL THEN 0
                  ELSE EXTRACT(EPOCH FROM ($6::text::timestamptz - $5::text::timestamptz))::integer
                END,
                NOW(),
                NOW()
              )
            "#,
            &[
                &id,
                &input.task_id,
                &auth.user_id,
                &description,
                &input.start_time,
                &end_time,
            ],
        )
        .await
        .map_err(database_error)?;
    let task = task_by_id(&state.database, &input.task_id).await?;
    publish_task_event(
        &state,
        "TIME_ENTRY_UPDATED",
        task.project_id,
        input.task_id,
        &auth,
        &headers,
    );
    Ok(Json(time_entry_by_id(&state, &id).await?))
}

async fn update_time_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateTimeEntryInput>,
) -> Result<Json<TimeEntryRecord>, ApiError> {
    let (task_id, workspace_id) = time_entry_context(&state, &id).await?;
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    let end_time = input.end_time.unwrap_or_default();
    let updated = if let Some(description) = input.description {
        state
            .database
            .client
            .execute(
                r#"
                  UPDATE time_entry
                  SET start_time = $1::text::timestamptz AT TIME ZONE 'UTC',
                      end_time = NULLIF($2, '')::text::timestamptz AT TIME ZONE 'UTC',
                      duration = CASE
                        WHEN NULLIF($2, '') IS NULL THEN NULL
                        ELSE EXTRACT(EPOCH FROM ($2::text::timestamptz - $1::text::timestamptz))::integer
                      END,
                      description = $3,
                      updated_at = NOW()
                  WHERE id = $4
                "#,
                &[&input.start_time, &end_time, &description, &id],
            )
            .await
            .map_err(database_error)?
    } else {
        state
            .database
            .client
            .execute(
                r#"
                  UPDATE time_entry
                  SET start_time = $1::text::timestamptz AT TIME ZONE 'UTC',
                      end_time = NULLIF($2, '')::text::timestamptz AT TIME ZONE 'UTC',
                      duration = CASE
                        WHEN NULLIF($2, '') IS NULL THEN NULL
                        ELSE EXTRACT(EPOCH FROM ($2::text::timestamptz - $1::text::timestamptz))::integer
                      END,
                      updated_at = NOW()
                  WHERE id = $3
                "#,
                &[&input.start_time, &end_time, &id],
            )
            .await
            .map_err(database_error)?
    };
    if updated == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Time entry not found"));
    }
    let task = task_by_id(&state.database, &task_id).await?;
    publish_task_event(
        &state,
        "TIME_ENTRY_UPDATED",
        task.project_id,
        task_id,
        &auth,
        &headers,
    );
    Ok(Json(time_entry_by_id(&state, &id).await?))
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

fn notification_preference_column(notification_type: &str) -> Option<&'static str> {
    match notification_type {
        "task_assignee_changed" | "task_created" => Some("task_assignment_enabled"),
        "task_comment" | "task_mention" => Some("task_comment_enabled"),
        "task_status_changed" => Some("task_status_change_enabled"),
        "due_date_reminder" | "task_overdue" => Some("due_date_reminder_enabled"),
        _ => None,
    }
}

async fn create_user_notification(
    state: &AppState,
    user_id: &str,
    title: Option<&str>,
    content: Option<&str>,
    notification_type: &str,
    event_data: Option<&Value>,
    resource_id: Option<&str>,
    resource_type: Option<&str>,
) -> Result<Option<Value>, ApiError> {
    if let Some(preference_column) = notification_preference_column(notification_type) {
        let preference = state
            .database
            .client
            .query_opt(
                r#"
                  SELECT task_assignment_enabled, task_comment_enabled,
                         task_status_change_enabled, due_date_reminder_enabled
                  FROM user_notification_preference
                  WHERE user_id = $1
                  LIMIT 1
                "#,
                &[&user_id],
            )
            .await
            .map_err(database_error)?;
        if let Some(preference) = preference {
            let enabled = preference
                .try_get::<_, bool>(preference_column)
                .map_err(database_error)?;
            if !enabled {
                return Ok(None);
            }
        }
    }

    let id = Uuid::new_v4().to_string();
    let event_data_json = event_data.map(Value::to_string).unwrap_or_default();
    let resource_id = resource_id.unwrap_or_default().to_string();
    let resource_type = resource_type.unwrap_or_default().to_string();
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO notification
                (id, user_id, title, content, type, event_data, is_read,
                 resource_id, resource_type, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::jsonb, FALSE,
                      NULLIF($7, ''), NULLIF($8, ''), NOW(), NOW())
            "#,
            &[
                &id,
                &user_id,
                &title,
                &content,
                &notification_type,
                &event_data_json,
                &resource_id,
                &resource_type,
            ],
        )
        .await
        .map_err(database_error)?;
    let _ = state.events.send(SocketEvent {
        event_type: "NOTIFICATION_CREATED".to_string(),
        project_id: None,
        task_id: None,
        source_task_id: None,
        target_task_id: None,
        initiator_id: None,
    });
    Ok(Some(
        notifications_for_user(state, user_id, Some(&id)).await?,
    ))
}

async fn create_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateNotificationInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let notification = create_user_notification(
        &state,
        &auth.user_id,
        input.title.as_deref(),
        input.message.as_deref(),
        &input.notification_type,
        input.event_data.as_ref(),
        input.related_entity_id.as_deref(),
        input.related_entity_type.as_deref(),
    )
    .await?;
    Ok(Json(notification.unwrap_or(Value::Null)))
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

const NOTIFICATION_SECRET_PREFIX: &str = "enc:v1:";

fn notification_secret_key() -> Result<[u8; 32], ApiError> {
    let raw_key = env::var("NOTIFICATION_SECRET_ENCRYPTION_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "NOTIFICATION_SECRET_ENCRYPTION_KEY is required to store encrypted notification secrets",
            )
        })?;
    let digest = Sha256::digest(raw_key.as_bytes());
    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn decrypt_notification_secret(value: Option<&String>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !value.starts_with(NOTIFICATION_SECRET_PREFIX) {
        return Ok(Some(value.clone()));
    }

    let payload = &value[NOTIFICATION_SECRET_PREFIX.len()..];
    let mut parts = payload.split('.');
    let iv_part = parts.next().filter(|part| !part.is_empty());
    let tag_part = parts.next().filter(|part| !part.is_empty());
    let encrypted_part = parts.next().filter(|part| !part.is_empty());
    let (Some(iv_part), Some(tag_part), Some(encrypted_part)) = (iv_part, tag_part, encrypted_part)
    else {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid encrypted notification secret payload",
        ));
    };

    let iv = URL_SAFE_NO_PAD.decode(iv_part).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to decrypt notification secret",
        )
    })?;
    let auth_tag = URL_SAFE_NO_PAD.decode(tag_part).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to decrypt notification secret",
        )
    })?;
    let encrypted = URL_SAFE_NO_PAD.decode(encrypted_part).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to decrypt notification secret",
        )
    })?;
    if iv.len() != 12 || auth_tag.len() != 16 {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to decrypt notification secret",
        ));
    }

    let key = notification_secret_key().map_err(|error| {
        if error.status == StatusCode::INTERNAL_SERVER_ERROR
            && error.message.contains("required to store")
        {
            error
        } else {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to decrypt notification secret",
            )
        }
    })?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to decrypt notification secret",
        )
    })?;
    let mut sealed = encrypted;
    sealed.extend_from_slice(&auth_tag);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&iv), sealed.as_ref())
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to decrypt notification secret",
            )
        })?;
    String::from_utf8(plaintext).map(Some).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to decrypt notification secret",
        )
    })
}

fn encrypt_notification_secret(value: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };

    if value.starts_with(NOTIFICATION_SECRET_PREFIX) {
        let candidate = value.to_string();
        if decrypt_notification_secret(Some(&candidate)).is_ok() {
            return Ok(Some(candidate));
        }
    }

    let key = notification_secret_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to encrypt notification secret",
        )
    })?;
    let nonce_bytes = Uuid::new_v4();
    let nonce = &nonce_bytes.as_bytes()[..12];
    let sealed = cipher
        .encrypt(Nonce::from_slice(nonce), value.as_bytes())
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to encrypt notification secret",
            )
        })?;
    if sealed.len() < 16 {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to encrypt notification secret",
        ));
    }
    let split = sealed.len() - 16;
    let encrypted = &sealed[..split];
    let auth_tag = &sealed[split..];
    Ok(Some(format!(
        "{NOTIFICATION_SECRET_PREFIX}{}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(auth_tag),
        URL_SAFE_NO_PAD.encode(encrypted),
    )))
}

fn normalize_notification_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn merged_notification_string(
    input: &OptionalStringInput,
    existing: Option<&String>,
) -> Option<String> {
    match input {
        OptionalStringInput::Missing => existing.cloned(),
        OptionalStringInput::Null => None,
        OptionalStringInput::Value(value) => normalize_notification_string(Some(value)),
    }
}

fn notification_string_input(value: &OptionalStringInput) -> Option<Option<String>> {
    match value {
        OptionalStringInput::Missing => None,
        OptionalStringInput::Null => Some(None),
        OptionalStringInput::Value(value) => Some(normalize_notification_string(Some(value))),
    }
}

fn mask_notification_secret(value: Option<&String>) -> Option<String> {
    let value = value.filter(|value| !value.is_empty())?;
    let characters = value.chars().collect::<Vec<_>>();
    if characters.len() > 8 {
        let prefix = characters[..4].iter().collect::<String>();
        let suffix = characters[characters.len() - 4..]
            .iter()
            .collect::<String>();
        Some(format!("{prefix}…{suffix}"))
    } else {
        Some("••••".to_string())
    }
}

fn row_optional_string_from(row: Option<&Row>, name: &str) -> Result<Option<String>, ApiError> {
    row.map(|row| row_optional_string(row, name))
        .transpose()
        .map(|value| value.flatten())
}

fn row_bool_from(row: Option<&Row>, name: &str, fallback: bool) -> Result<bool, ApiError> {
    row.map(|row| row.try_get::<_, bool>(name).map_err(database_error))
        .transpose()
        .map(|value| value.unwrap_or(fallback))
}

fn row_i32_from(row: Option<&Row>, name: &str, fallback: i32) -> Result<i32, ApiError> {
    row.map(|row| row.try_get::<_, i32>(name).map_err(database_error))
        .transpose()
        .map(|value| value.unwrap_or(fallback))
}

fn is_private_notification_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            octets[0] == 0
                || octets[0] == 10
                || octets[0] == 127
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(address) => {
            let first = address.segments()[0];
            address.is_unspecified()
                || address.is_loopback()
                || (first & 0xffc0) == 0xfe80
                || (first & 0xfe00) == 0xfc00
        }
    }
}

async fn validate_notification_destination(value: &str) -> Result<(), ApiError> {
    let url = Url::parse(value).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid webhook URL: {error}"),
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook URL must use http or https",
        ));
    }
    if env::var("KANEO_ALLOW_PRIVATE_WEBHOOK_DESTINATIONS")
        .is_ok_and(|value| value == "true" || value == "1")
    {
        return Ok(());
    }

    let host = url.host_str().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook destination could not be resolved",
        )
    })?;
    if host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(is_private_notification_ip)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook destination resolves to a non-routable address",
        ));
    }

    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = lookup_host((host, port)).await.map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook destination could not be resolved",
        )
    })?;
    let mut found = false;
    for address in addresses {
        found = true;
        if is_private_notification_ip(address.ip()) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Generic webhook destination resolves to a non-routable address",
            ));
        }
    }
    if !found {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Generic webhook destination could not be resolved",
        ));
    }
    Ok(())
}

async fn notification_user_email(
    state: &AppState,
    user_id: &str,
) -> Result<Option<String>, ApiError> {
    state
        .database
        .client
        .query_opt(
            "SELECT email FROM \"user\" WHERE id = $1 LIMIT 1",
            &[&user_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_optional_string(&row, "email"))
        .transpose()
        .map(|value| value.flatten())
}

async fn notification_preferences_json(state: &AppState, user_id: &str) -> Result<Value, ApiError> {
    let email_address = notification_user_email(state, user_id).await?;
    let preference = state
        .database
        .client
        .query_opt(
            r#"
              SELECT email_enabled, ntfy_enabled, ntfy_server_url, ntfy_topic,
                     ntfy_token, gotify_enabled, gotify_server_url, gotify_token,
                     webhook_enabled, webhook_url, webhook_secret,
                     task_assignment_enabled, task_comment_enabled,
                     task_status_change_enabled, due_date_reminder_enabled,
                     due_date_reminder_lead_time_minutes,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM user_notification_preference
              WHERE user_id = $1
              LIMIT 1
            "#,
            &[&user_id],
        )
        .await
        .map_err(database_error)?;

    let raw_ntfy_token = row_optional_string_from(preference.as_ref(), "ntfy_token")?;
    let raw_gotify_token = row_optional_string_from(preference.as_ref(), "gotify_token")?;
    let raw_webhook_secret = row_optional_string_from(preference.as_ref(), "webhook_secret")?;
    let ntfy_token = decrypt_notification_secret(raw_ntfy_token.as_ref())?;
    let gotify_token = decrypt_notification_secret(raw_gotify_token.as_ref())?;
    let webhook_secret = decrypt_notification_secret(raw_webhook_secret.as_ref())?;
    let ntfy_server_url = row_optional_string_from(preference.as_ref(), "ntfy_server_url")?;
    let ntfy_topic = row_optional_string_from(preference.as_ref(), "ntfy_topic")?;
    let gotify_server_url = row_optional_string_from(preference.as_ref(), "gotify_server_url")?;
    let webhook_url = row_optional_string_from(preference.as_ref(), "webhook_url")?;

    let rules = state
        .database
        .client
        .query(
            r#"
              SELECT r.id, r.workspace_id, w.name AS workspace_name,
                     r.is_active, r.email_enabled, r.ntfy_enabled,
                     r.gotify_enabled, r.webhook_enabled, r.project_mode,
                     to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(r.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM user_notification_workspace_rule r
              INNER JOIN workspace w ON w.id = r.workspace_id
              WHERE r.user_id = $1
              ORDER BY r.created_at ASC
            "#,
            &[&user_id],
        )
        .await
        .map_err(database_error)?;
    let selected_projects = state
        .database
        .client
        .query(
            r#"
              SELECT p.workspace_rule_id, p.project_id
              FROM user_notification_workspace_project p
              INNER JOIN user_notification_workspace_rule r
                ON r.id = p.workspace_rule_id
              WHERE r.user_id = $1
            "#,
            &[&user_id],
        )
        .await
        .map_err(database_error)?;
    let mut projects_by_rule = HashMap::<String, Vec<String>>::new();
    for row in selected_projects {
        projects_by_rule
            .entry(row_string(&row, "workspace_rule_id")?)
            .or_default()
            .push(row_string(&row, "project_id")?);
    }

    let workspace_rules = rules
        .into_iter()
        .map(|row| {
            let id = row_string(&row, "id")?;
            let project_mode = row_string(&row, "project_mode")?;
            Ok(json!({
                "id": id.clone(),
                "workspaceId": row_string(&row, "workspace_id")?,
                "workspaceName": row_string(&row, "workspace_name")?,
                "isActive": row.try_get::<_, bool>("is_active").map_err(database_error)?,
                "emailEnabled": row.try_get::<_, bool>("email_enabled").map_err(database_error)?,
                "ntfyEnabled": row.try_get::<_, bool>("ntfy_enabled").map_err(database_error)?,
                "gotifyEnabled": row.try_get::<_, bool>("gotify_enabled").map_err(database_error)?,
                "webhookEnabled": row.try_get::<_, bool>("webhook_enabled").map_err(database_error)?,
                "projectMode": if project_mode == "selected" { "selected" } else { "all" },
                "selectedProjectIds": projects_by_rule.remove(&id).unwrap_or_default(),
                "createdAt": row_string(&row, "created_at")?,
                "updatedAt": row_string(&row, "updated_at")?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    Ok(json!({
        "emailAddress": email_address,
        "emailEnabled": row_bool_from(preference.as_ref(), "email_enabled", false)?,
        "ntfyEnabled": row_bool_from(preference.as_ref(), "ntfy_enabled", false)?,
        "ntfyConfigured": ntfy_server_url.is_some() && ntfy_topic.is_some(),
        "ntfyServerUrl": ntfy_server_url,
        "ntfyTopic": ntfy_topic,
        "ntfyTokenConfigured": ntfy_token.is_some(),
        "maskedNtfyToken": mask_notification_secret(ntfy_token.as_ref()),
        "gotifyEnabled": row_bool_from(preference.as_ref(), "gotify_enabled", false)?,
        "gotifyConfigured": gotify_server_url.is_some() && gotify_token.is_some(),
        "gotifyServerUrl": gotify_server_url,
        "gotifyTokenConfigured": gotify_token.is_some(),
        "maskedGotifyToken": mask_notification_secret(gotify_token.as_ref()),
        "webhookEnabled": row_bool_from(preference.as_ref(), "webhook_enabled", false)?,
        "webhookConfigured": webhook_url.is_some(),
        "webhookUrl": webhook_url,
        "webhookSecretConfigured": webhook_secret.is_some(),
        "maskedWebhookSecret": mask_notification_secret(webhook_secret.as_ref()),
        "taskAssignmentEnabled": row_bool_from(preference.as_ref(), "task_assignment_enabled", true)?,
        "taskCommentEnabled": row_bool_from(preference.as_ref(), "task_comment_enabled", true)?,
        "taskStatusChangeEnabled": row_bool_from(preference.as_ref(), "task_status_change_enabled", true)?,
        "dueDateReminderEnabled": row_bool_from(preference.as_ref(), "due_date_reminder_enabled", true)?,
        "dueDateReminderLeadTimeMinutes": row_i32_from(preference.as_ref(), "due_date_reminder_lead_time_minutes", 1440)?,
        "workspaces": workspace_rules,
        "createdAt": row_optional_string_from(preference.as_ref(), "created_at")?,
        "updatedAt": row_optional_string_from(preference.as_ref(), "updated_at")?,
    }))
}

async fn require_notification_workspace_membership(
    state: &AppState,
    user_id: &str,
    workspace_id: &str,
) -> Result<(), ApiError> {
    let member = state
        .database
        .client
        .query_opt(
            "SELECT 1 FROM workspace_member WHERE user_id = $1 AND workspace_id = $2 LIMIT 1",
            &[&user_id, &workspace_id],
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

async fn validate_notification_project_selection(
    state: &AppState,
    workspace_id: &str,
    project_ids: &[String],
) -> Result<(), ApiError> {
    if project_ids.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Select at least one project for selected project mode",
        ));
    }
    let unique = project_ids.iter().collect::<HashSet<_>>();
    if unique.len() != project_ids.len() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "One or more selected projects are invalid",
        ));
    }
    for project_id in project_ids {
        let project = state
            .database
            .client
            .query_opt(
                "SELECT 1 FROM project WHERE id = $1 AND workspace_id = $2 LIMIT 1",
                &[&project_id, &workspace_id],
            )
            .await
            .map_err(database_error)?;
        if project.is_none() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "One or more selected projects are invalid",
            ));
        }
    }
    Ok(())
}

async fn get_notification_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    Ok(Json(
        notification_preferences_json(&state, &auth.user_id).await?,
    ))
}

async fn update_notification_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateNotificationPreferencesInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let email_address = notification_user_email(&state, &auth.user_id).await?;
    let existing = state
        .database
        .client
        .query_opt(
            r#"
              SELECT email_enabled, ntfy_enabled, ntfy_server_url, ntfy_topic,
                     ntfy_token, gotify_enabled, gotify_server_url, gotify_token,
                     webhook_enabled, webhook_url, webhook_secret,
                     task_assignment_enabled, task_comment_enabled,
                     task_status_change_enabled, due_date_reminder_enabled,
                     due_date_reminder_lead_time_minutes
              FROM user_notification_preference
              WHERE user_id = $1
              LIMIT 1
            "#,
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;

    let existing_ntfy_server_url = row_optional_string_from(existing.as_ref(), "ntfy_server_url")?;
    let existing_ntfy_topic = row_optional_string_from(existing.as_ref(), "ntfy_topic")?;
    let existing_gotify_server_url =
        row_optional_string_from(existing.as_ref(), "gotify_server_url")?;
    let existing_webhook_url = row_optional_string_from(existing.as_ref(), "webhook_url")?;
    let existing_ntfy_token_raw = row_optional_string_from(existing.as_ref(), "ntfy_token")?;
    let existing_gotify_token_raw = row_optional_string_from(existing.as_ref(), "gotify_token")?;
    let existing_webhook_secret_raw =
        row_optional_string_from(existing.as_ref(), "webhook_secret")?;
    let _existing_ntfy_token = decrypt_notification_secret(existing_ntfy_token_raw.as_ref())?;
    let existing_gotify_token = decrypt_notification_secret(existing_gotify_token_raw.as_ref())?;
    let _existing_webhook_secret =
        decrypt_notification_secret(existing_webhook_secret_raw.as_ref())?;

    let email_enabled =
        input
            .email_enabled
            .unwrap_or(row_bool_from(existing.as_ref(), "email_enabled", false)?);
    let ntfy_enabled =
        input
            .ntfy_enabled
            .unwrap_or(row_bool_from(existing.as_ref(), "ntfy_enabled", false)?);
    let gotify_enabled =
        input
            .gotify_enabled
            .unwrap_or(row_bool_from(existing.as_ref(), "gotify_enabled", false)?);
    let webhook_enabled = input.webhook_enabled.unwrap_or(row_bool_from(
        existing.as_ref(),
        "webhook_enabled",
        false,
    )?);
    let ntfy_server_url =
        merged_notification_string(&input.ntfy_server_url, existing_ntfy_server_url.as_ref());
    let ntfy_topic = merged_notification_string(&input.ntfy_topic, existing_ntfy_topic.as_ref());
    let gotify_server_url = merged_notification_string(
        &input.gotify_server_url,
        existing_gotify_server_url.as_ref(),
    );
    let webhook_url = merged_notification_string(&input.webhook_url, existing_webhook_url.as_ref());
    let ntfy_token_input = notification_string_input(&input.ntfy_token);
    let gotify_token_input = notification_string_input(&input.gotify_token);
    let webhook_secret_input = notification_string_input(&input.webhook_secret);
    let gotify_token = match &input.gotify_token {
        OptionalStringInput::Missing => existing_gotify_token.clone(),
        OptionalStringInput::Null => None,
        OptionalStringInput::Value(_) => gotify_token_input.clone().flatten(),
    };

    let due_date_reminder_lead_time_minutes =
        input
            .due_date_reminder_lead_time_minutes
            .unwrap_or(row_i32_from(
                existing.as_ref(),
                "due_date_reminder_lead_time_minutes",
                1440,
            )?);
    if !(5..=43_200).contains(&due_date_reminder_lead_time_minutes) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "dueDateReminderLeadTimeMinutes must be between 5 and 43200",
        ));
    }
    if email_enabled && email_address.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Email notifications require an account email address",
        ));
    }

    let should_validate_ntfy = ntfy_enabled
        || !matches!(&input.ntfy_server_url, OptionalStringInput::Missing)
        || !matches!(&input.ntfy_topic, OptionalStringInput::Missing)
        || !matches!(&input.ntfy_token, OptionalStringInput::Missing);
    let should_validate_gotify = gotify_enabled
        || !matches!(&input.gotify_server_url, OptionalStringInput::Missing)
        || !matches!(&input.gotify_token, OptionalStringInput::Missing);
    let should_validate_webhook = webhook_enabled
        || !matches!(&input.webhook_url, OptionalStringInput::Missing)
        || !matches!(&input.webhook_secret, OptionalStringInput::Missing);

    if should_validate_ntfy {
        let Some(server_url) = ntfy_server_url.as_deref() else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "ntfy requires a server URL and topic",
            ));
        };
        if ntfy_topic.is_none() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "ntfy requires a server URL and topic",
            ));
        }
        validate_notification_destination(server_url)
            .await
            .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.message))?;
    }
    if should_validate_gotify {
        let Some(server_url) = gotify_server_url.as_deref() else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Gotify requires a server URL and app token",
            ));
        };
        if gotify_token.is_none() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Gotify requires a server URL and app token",
            ));
        }
        validate_notification_destination(server_url)
            .await
            .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.message))?;
    }
    if should_validate_webhook {
        let Some(webhook_url) = webhook_url.as_deref() else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Webhook notifications require an endpoint URL",
            ));
        };
        validate_notification_destination(webhook_url)
            .await
            .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.message))?;
    }

    let stored_ntfy_token = if !matches!(&input.ntfy_token, OptionalStringInput::Missing) {
        encrypt_notification_secret(ntfy_token_input.as_ref().and_then(|value| value.as_deref()))?
    } else {
        existing_ntfy_token_raw.clone()
    };
    let stored_gotify_token = if !matches!(&input.gotify_token, OptionalStringInput::Missing) {
        encrypt_notification_secret(
            gotify_token_input
                .as_ref()
                .and_then(|value| value.as_deref()),
        )?
    } else {
        existing_gotify_token_raw.clone()
    };
    let stored_webhook_secret = if !matches!(&input.webhook_secret, OptionalStringInput::Missing) {
        encrypt_notification_secret(
            webhook_secret_input
                .as_ref()
                .and_then(|value| value.as_deref()),
        )?
    } else {
        existing_webhook_secret_raw.clone()
    };
    let task_assignment_enabled = input.task_assignment_enabled.unwrap_or(row_bool_from(
        existing.as_ref(),
        "task_assignment_enabled",
        true,
    )?);
    let task_comment_enabled = input.task_comment_enabled.unwrap_or(row_bool_from(
        existing.as_ref(),
        "task_comment_enabled",
        true,
    )?);
    let task_status_change_enabled = input.task_status_change_enabled.unwrap_or(row_bool_from(
        existing.as_ref(),
        "task_status_change_enabled",
        true,
    )?);
    let due_date_reminder_enabled = input.due_date_reminder_enabled.unwrap_or(row_bool_from(
        existing.as_ref(),
        "due_date_reminder_enabled",
        true,
    )?);

    if existing.is_some() {
        state
            .database
            .client
            .execute(
                r#"
                  UPDATE user_notification_preference
                  SET email_enabled = $2, ntfy_enabled = $3,
                      ntfy_server_url = $4, ntfy_topic = $5, ntfy_token = $6,
                      gotify_enabled = $7, gotify_server_url = $8, gotify_token = $9,
                      webhook_enabled = $10, webhook_url = $11, webhook_secret = $12,
                      task_assignment_enabled = $13, task_comment_enabled = $14,
                      task_status_change_enabled = $15, due_date_reminder_enabled = $16,
                      due_date_reminder_lead_time_minutes = $17, updated_at = NOW()
                  WHERE user_id = $1
                "#,
                &[
                    &auth.user_id,
                    &email_enabled,
                    &ntfy_enabled,
                    &ntfy_server_url,
                    &ntfy_topic,
                    &stored_ntfy_token,
                    &gotify_enabled,
                    &gotify_server_url,
                    &stored_gotify_token,
                    &webhook_enabled,
                    &webhook_url,
                    &stored_webhook_secret,
                    &task_assignment_enabled,
                    &task_comment_enabled,
                    &task_status_change_enabled,
                    &due_date_reminder_enabled,
                    &due_date_reminder_lead_time_minutes,
                ],
            )
            .await
            .map_err(database_error)?;
    } else {
        let id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO user_notification_preference
                    (id, user_id, email_enabled, ntfy_enabled, ntfy_server_url,
                     ntfy_topic, ntfy_token, gotify_enabled, gotify_server_url,
                     gotify_token, webhook_enabled, webhook_url, webhook_secret,
                     task_assignment_enabled, task_comment_enabled,
                     task_status_change_enabled, due_date_reminder_enabled,
                     due_date_reminder_lead_time_minutes, created_at, updated_at)
                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                          $13, $14, $15, $16, $17, $18, NOW(), NOW())
                "#,
                &[
                    &id,
                    &auth.user_id,
                    &email_enabled,
                    &ntfy_enabled,
                    &ntfy_server_url,
                    &ntfy_topic,
                    &stored_ntfy_token,
                    &gotify_enabled,
                    &gotify_server_url,
                    &stored_gotify_token,
                    &webhook_enabled,
                    &webhook_url,
                    &stored_webhook_secret,
                    &task_assignment_enabled,
                    &task_comment_enabled,
                    &task_status_change_enabled,
                    &due_date_reminder_enabled,
                    &due_date_reminder_lead_time_minutes,
                ],
            )
            .await
            .map_err(database_error)?;
    }

    let previous_email_enabled = row_bool_from(existing.as_ref(), "email_enabled", false)?;
    let previous_ntfy_enabled = row_bool_from(existing.as_ref(), "ntfy_enabled", false)?;
    let previous_gotify_enabled = row_bool_from(existing.as_ref(), "gotify_enabled", false)?;
    let previous_webhook_enabled = row_bool_from(existing.as_ref(), "webhook_enabled", false)?;
    let disable_email = !email_enabled;
    let enable_email = email_enabled && !previous_email_enabled && email_address.is_some();
    let disable_ntfy = !ntfy_enabled || ntfy_server_url.is_none() || ntfy_topic.is_none();
    let enable_ntfy =
        ntfy_enabled && !previous_ntfy_enabled && ntfy_server_url.is_some() && ntfy_topic.is_some();
    let disable_gotify = !gotify_enabled || gotify_server_url.is_none() || gotify_token.is_none();
    let enable_gotify = gotify_enabled
        && !previous_gotify_enabled
        && gotify_server_url.is_some()
        && gotify_token.is_some();
    let disable_webhook = !webhook_enabled || webhook_url.is_none();
    let enable_webhook = webhook_enabled && !previous_webhook_enabled && webhook_url.is_some();
    if disable_email
        || enable_email
        || disable_ntfy
        || enable_ntfy
        || disable_gotify
        || enable_gotify
        || disable_webhook
        || enable_webhook
    {
        state
            .database
            .client
            .execute(
                r#"
                  UPDATE user_notification_workspace_rule
                  SET email_enabled = CASE WHEN $2 THEN FALSE WHEN $3 THEN TRUE ELSE email_enabled END,
                      ntfy_enabled = CASE WHEN $4 THEN FALSE WHEN $5 THEN TRUE ELSE ntfy_enabled END,
                      gotify_enabled = CASE WHEN $6 THEN FALSE WHEN $7 THEN TRUE ELSE gotify_enabled END,
                      webhook_enabled = CASE WHEN $8 THEN FALSE WHEN $9 THEN TRUE ELSE webhook_enabled END,
                      updated_at = NOW()
                  WHERE user_id = $1 AND is_active = TRUE
                    AND (email_enabled = TRUE OR ntfy_enabled = TRUE
                      OR gotify_enabled = TRUE OR webhook_enabled = TRUE)
                "#,
                &[
                    &auth.user_id,
                    &disable_email,
                    &enable_email,
                    &disable_ntfy,
                    &enable_ntfy,
                    &disable_gotify,
                    &enable_gotify,
                    &disable_webhook,
                    &enable_webhook,
                ],
            )
            .await
            .map_err(database_error)?;
    }

    Ok(Json(
        notification_preferences_json(&state, &auth.user_id).await?,
    ))
}

async fn upsert_notification_workspace_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(input): Json<NotificationWorkspaceRuleInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_notification_workspace_membership(&state, &auth.user_id, &workspace_id).await?;
    if !matches!(input.project_mode.as_str(), "all" | "selected") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid notification project mode",
        ));
    }
    let selected_project_ids = input.selected_project_ids.clone().unwrap_or_default();
    if input.project_mode == "selected" {
        validate_notification_project_selection(&state, &workspace_id, &selected_project_ids)
            .await?;
    }

    let preference = state
        .database
        .client
        .query_opt(
            r#"
              SELECT email_enabled, ntfy_enabled, ntfy_server_url, ntfy_topic,
                     gotify_enabled, gotify_server_url, gotify_token,
                     webhook_enabled, webhook_url
              FROM user_notification_preference
              WHERE user_id = $1
              LIMIT 1
            "#,
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;
    let email_address = notification_user_email(&state, &auth.user_id).await?;
    let global_email_enabled = row_bool_from(preference.as_ref(), "email_enabled", false)?;
    let global_ntfy_enabled = row_bool_from(preference.as_ref(), "ntfy_enabled", false)?;
    let global_gotify_enabled = row_bool_from(preference.as_ref(), "gotify_enabled", false)?;
    let global_webhook_enabled = row_bool_from(preference.as_ref(), "webhook_enabled", false)?;
    let global_ntfy_server_url = row_optional_string_from(preference.as_ref(), "ntfy_server_url")?;
    let global_ntfy_topic = row_optional_string_from(preference.as_ref(), "ntfy_topic")?;
    let global_gotify_server_url =
        row_optional_string_from(preference.as_ref(), "gotify_server_url")?;
    let global_gotify_token = row_optional_string_from(preference.as_ref(), "gotify_token")?;
    let global_webhook_url = row_optional_string_from(preference.as_ref(), "webhook_url")?;

    if input.email_enabled && (!global_email_enabled || email_address.is_none()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Enable email notifications globally before using them here",
        ));
    }
    if input.ntfy_enabled
        && (!global_ntfy_enabled || global_ntfy_server_url.is_none() || global_ntfy_topic.is_none())
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Enable ntfy notifications globally before using them here",
        ));
    }
    if input.webhook_enabled && (!global_webhook_enabled || global_webhook_url.is_none()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Enable webhook notifications globally before using them here",
        ));
    }
    if input.gotify_enabled
        && (!global_gotify_enabled
            || global_gotify_server_url.is_none()
            || global_gotify_token.is_none())
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Enable Gotify notifications globally before using them here",
        ));
    }

    let existing = state
        .database
        .client
        .query_opt(
            "SELECT id FROM user_notification_workspace_rule WHERE user_id = $1 AND workspace_id = $2 LIMIT 1",
            &[&auth.user_id, &workspace_id],
        )
        .await
        .map_err(database_error)?;
    let rule_id = existing
        .as_ref()
        .map(|row| row_string(row, "id"))
        .transpose()?
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if existing.is_some() {
        state
            .database
            .client
            .execute(
                r#"
                  UPDATE user_notification_workspace_rule
                  SET is_active = $3, email_enabled = $4, ntfy_enabled = $5,
                      gotify_enabled = $6, webhook_enabled = $7, project_mode = $8,
                      updated_at = NOW()
                  WHERE user_id = $1 AND workspace_id = $2
                "#,
                &[
                    &auth.user_id,
                    &workspace_id,
                    &input.is_active,
                    &input.email_enabled,
                    &input.ntfy_enabled,
                    &input.gotify_enabled,
                    &input.webhook_enabled,
                    &input.project_mode,
                ],
            )
            .await
            .map_err(database_error)?;
    } else {
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO user_notification_workspace_rule
                    (id, user_id, workspace_id, is_active, email_enabled,
                     ntfy_enabled, gotify_enabled, webhook_enabled, project_mode,
                     created_at, updated_at)
                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
                "#,
                &[
                    &rule_id,
                    &auth.user_id,
                    &workspace_id,
                    &input.is_active,
                    &input.email_enabled,
                    &input.ntfy_enabled,
                    &input.gotify_enabled,
                    &input.webhook_enabled,
                    &input.project_mode,
                ],
            )
            .await
            .map_err(database_error)?;
    }

    state
        .database
        .client
        .execute(
            "DELETE FROM user_notification_workspace_project WHERE workspace_rule_id = $1",
            &[&rule_id],
        )
        .await
        .map_err(database_error)?;
    if input.project_mode == "selected" {
        for project_id in selected_project_ids {
            let id = Uuid::new_v4().to_string();
            state
                .database
                .client
                .execute(
                    r#"
                      INSERT INTO user_notification_workspace_project
                        (id, workspace_id, workspace_rule_id, project_id, created_at, updated_at)
                      VALUES ($1, $2, $3, $4, NOW(), NOW())
                    "#,
                    &[&id, &workspace_id, &rule_id, &project_id],
                )
                .await
                .map_err(database_error)?;
        }
    }

    Ok(Json(
        notification_preferences_json(&state, &auth.user_id).await?,
    ))
}

async fn delete_notification_workspace_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_notification_workspace_membership(&state, &auth.user_id, &workspace_id).await?;
    let existing = state
        .database
        .client
        .query_opt(
            "SELECT id FROM user_notification_workspace_rule WHERE user_id = $1 AND workspace_id = $2 LIMIT 1",
            &[&auth.user_id, &workspace_id],
        )
        .await
        .map_err(database_error)?;
    let Some(existing) = existing else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Workspace notification rule not found",
        ));
    };
    let rule_id = row_string(&existing, "id")?;
    state
        .database
        .client
        .execute(
            "DELETE FROM user_notification_workspace_rule WHERE id = $1",
            &[&rule_id],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(
        notification_preferences_json(&state, &auth.user_id).await?,
    ))
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

async fn public_invitation_details(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT i.id, i.email, w.name AS workspace_name, u.name AS inviter_name,
                     to_char(i.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     i.status, (i.expires_at < NOW()) AS expired
              FROM invitation i
              INNER JOIN workspace w ON w.id = i.workspace_id
              INNER JOIN "user" u ON u.id = i.inviter_id
              WHERE i.id = $1
              LIMIT 1
            "#,
            &[&id],
        )
        .await
        .map_err(database_error)?;
    let Some(row) = row else {
        return Ok(Json(json!({
            "valid": false,
            "error": "Invitation not found",
        })));
    };

    let status = row_string(&row, "status")?;
    let expired = row.try_get::<_, bool>("expired").map_err(database_error)?;
    let invitation = json!({
        "id": row_string(&row, "id")?,
        "email": row_string(&row, "email")?,
        "workspaceName": row_string(&row, "workspace_name")?,
        "inviterName": row_string(&row, "inviter_name")?,
        "expiresAt": row_string(&row, "expires_at")?,
        "status": status,
        "expired": expired,
    });
    if status == "accepted" {
        return Ok(Json(json!({
            "valid": false,
            "error": "This invitation has already been accepted",
        })));
    }
    if status == "canceled" {
        return Ok(Json(json!({
            "valid": false,
            "error": "This invitation has been canceled",
        })));
    }
    if expired {
        return Ok(Json(json!({
            "valid": false,
            "invitation": invitation,
            "error": "This invitation has expired",
        })));
    }
    Ok(Json(json!({
        "valid": true,
        "invitation": invitation,
    })))
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
        .route("/api/instance/status", get(instance_status))
        .route("/api/rust/status", get(rust_status))
        .route("/api/public-project/{id}", get(get_public_project))
        .route("/api/search", get(global_search))
        .route("/api/auth/get-session", get(get_session))
        .route("/api/oauth/id-token", get(get_oauth_id_token))
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
        .route(
            "/api/notification",
            get(list_notifications).post(create_notification),
        )
        .route(
            "/api/notification/{id}/read",
            patch(mark_notification_as_read),
        )
        .route(
            "/api/notification/read-all",
            patch(mark_all_notifications_as_read),
        )
        .route("/api/notification/clear-all", delete(clear_notifications))
        .route(
            "/api/notification-preferences",
            get(get_notification_preferences).put(update_notification_preferences),
        )
        .route(
            "/api/notification-preferences/workspaces/{workspace_id}",
            put(upsert_notification_workspace_rule).delete(delete_notification_workspace_rule),
        )
        .route(
            "/api/generic-webhook-integration/project/{project_id}",
            get(get_generic_webhook_integration)
                .post(create_generic_webhook_integration)
                .patch(update_generic_webhook_integration)
                .delete(delete_generic_webhook_integration),
        )
        .route("/api/invitation/pending", get(pending_invitations))
        .route(
            "/api/invitation/public/{id}",
            get(public_invitation_details),
        )
        .route("/api/billing/{workspace_id}", get(get_workspace_billing))
        .route(
            "/api/workspace/{workspace_id}/members",
            get(list_workspace_members),
        )
        .route("/api/label/task/{task_id}", get(list_task_labels))
        .route(
            "/api/label/workspace/{workspace_id}",
            get(list_workspace_labels),
        )
        .route(
            "/api/label/{id}",
            get(get_label).put(update_label).delete(delete_label),
        )
        .route(
            "/api/label/{id}/task",
            put(assign_label_to_task).delete(unassign_label_from_task),
        )
        .route("/api/label", post(create_label))
        .route(
            "/api/external-link/task/{task_id}",
            get(list_external_links),
        )
        .route("/api/activity/{task_id}", get(list_activities))
        .route("/api/activity/create", post(create_activity))
        .route(
            "/api/activity/comment",
            post(create_activity_comment)
                .put(update_activity_comment)
                .delete(delete_activity_comment),
        )
        .route(
            "/api/comment/{id}",
            get(list_comments)
                .post(create_comment)
                .put(update_comment)
                .delete(delete_comment),
        )
        .route("/api/task-relation", post(create_task_relation))
        .route(
            "/api/task-relation/{id}",
            get(list_task_relations).delete(delete_task_relation),
        )
        .route("/api/time-entry", post(create_time_entry))
        .route("/api/time-entry/", post(create_time_entry))
        .route("/api/time-entry/task/{task_id}", get(list_time_entries))
        .route(
            "/api/time-entry/{id}",
            get(get_time_entry).put(update_time_entry),
        )
        .route("/api/project", get(list_projects).post(create_project))
        .route(
            "/api/project/{id}",
            get(get_project).put(update_project).delete(delete_project),
        )
        .route("/api/project/{id}/archive", put(archive_project))
        .route("/api/project/{id}/unarchive", put(unarchive_project))
        .route(
            "/api/column/{id}",
            get(list_columns)
                .post(create_column)
                .put(update_column)
                .delete(delete_column),
        )
        .route("/api/column/reorder/{project_id}", put(reorder_columns))
        .route(
            "/api/workflow-rule/{project_id}",
            get(list_workflow_rules)
                .put(upsert_workflow_rule)
                .delete(delete_workflow_rule),
        )
        .route("/api/task/tasks/{project_id}", get(list_tasks))
        .route("/api/task/bulk", patch(bulk_update_tasks))
        .route("/api/task/import/{project_id}", post(import_tasks))
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
        .route("/api/task/assignee/{id}", put(update_task_assignee))
        .route("/api/task/description/{id}", put(update_task_description))
        .route("/api/task/move/{id}", put(move_task))
        .route("/api/task/export/{project_id}", get(export_tasks))
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
