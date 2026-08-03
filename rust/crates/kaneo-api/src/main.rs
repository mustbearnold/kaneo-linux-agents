//! Rust runtime for Kaneo's authenticated API, board, integrations, and
//! autonomous agent execution.
//!
//! The desktop runtime starts this server as the only Kaneo API process. A
//! missing route is returned as a native Rust 404 rather than being silently
//! forwarded to a second implementation.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bcrypt::{hash as bcrypt_hash, verify as bcrypt_verify};
use chrono::Utc;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, EncodingKey, Header as JwtHeader, encode};
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, lookup_host};
use tokio::sync::{Mutex, broadcast};
use tokio_postgres::{Client, NoTls, Row};
use url::Url;
use uuid::Uuid;

const DEFAULT_BIND: &str = "127.0.0.1:1337";
const DEFAULT_MAX_BODY_BYTES: usize = 20 * 1024 * 1024;
const MAX_ORCHESTRATOR_DEPTH: usize = 8;
const MAX_ORCHESTRATOR_RESPONSE_DEPTH: usize = 8;

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
    orchestrator_runner: RunManager,
    orchestrators: Arc<Mutex<OrchestratorState>>,
    http: reqwest::Client,
    api_base_url: String,
    client_url: String,
    mcp: Arc<Mutex<McpState>>,
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

#[derive(Clone)]
struct McpRegisteredClient {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    issued_at: i64,
}

#[derive(Clone)]
struct McpAuthorizationRequest {
    client_id: String,
    code_challenge: String,
    redirect_uri: String,
    state: Option<String>,
    expires_at: i64,
}

#[derive(Clone)]
struct McpAuthorizationCode {
    client_id: String,
    user_id: String,
    code_challenge: String,
    redirect_uri: String,
    expires_at: i64,
}

#[derive(Default)]
struct McpState {
    clients: HashMap<String, McpRegisteredClient>,
    authorization_requests: HashMap<String, McpAuthorizationRequest>,
    codes: HashMap<String, McpAuthorizationCode>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignUpInput {
    name: String,
    email: String,
    password: String,
    #[serde(default)]
    locale: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignInInput {
    email: String,
    password: String,
    #[serde(default)]
    #[serde(rename = "rememberMe")]
    _remember_me: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct OrganizationCreateInput {
    name: String,
    slug: Option<String>,
    logo: Option<String>,
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct OrganizationUpdateData {
    name: Option<String>,
    slug: Option<String>,
    logo: Option<Option<String>>,
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct OrganizationUpdateInput {
    organization_id: Option<String>,
    organization_slug: Option<String>,
    data: Option<OrganizationUpdateData>,
    name: Option<String>,
    slug: Option<String>,
    logo: Option<Option<String>>,
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct OrganizationSelectInput {
    organization_id: Option<String>,
    organization_slug: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ApiKeyCreateInput {
    name: Option<String>,
    expires_in: Option<i64>,
    prefix: Option<String>,
    metadata: Option<Value>,
    permissions: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeyDeleteInput {
    key_id: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct UpdateUserInput {
    name: Option<String>,
    image: Option<Option<String>>,
    locale: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordInput {
    current_password: String,
    new_password: String,
    #[serde(default)]
    revoke_other_sessions: bool,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeCreateInput {
    client_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceCodeUserInput {
    user_code: String,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenInput {
    grant_type: String,
    device_code: String,
    client_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskImageUploadInput {
    filename: String,
    content_type: String,
    size: i64,
    surface: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskImageFinalizeInput {
    key: String,
    filename: String,
    content_type: String,
    size: i64,
    surface: String,
}

#[derive(Debug, Deserialize)]
struct BillingCheckoutInput {
    plan: String,
    interval: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct OrganizationMemberInput {
    organization_id: Option<String>,
    member_id: Option<String>,
    member_id_or_email: Option<String>,
    role: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteMemberInput {
    organization_id: String,
    email: String,
    role: Option<String>,
    resend: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InvitationActionInput {
    invitation_id: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RoleCreateInput {
    organization_id: String,
    role: String,
    permission: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RoleUpdateInput {
    organization_id: String,
    role_name: String,
    data: Option<RoleUpdateData>,
    permission: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Deserialize, Default)]
struct RoleUpdateData {
    permission: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleDeleteInput {
    organization_id: String,
    role_name: String,
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
struct CreateGithubIntegrationInput {
    repository_owner: String,
    repository_name: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct UpdateGithubIntegrationInput {
    is_active: Option<bool>,
    comment_task_link_on_github_issue: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyGithubInput {
    repository_owner: String,
    repository_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GiteaRepositoriesInput {
    base_url: String,
    access_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyGiteaInput {
    base_url: String,
    access_token: String,
    repository_owner: String,
    repository_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportIntegrationInput {
    project_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateGiteaIntegrationInput {
    base_url: String,
    access_token: Option<String>,
    repository_owner: String,
    repository_name: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct UpdateGiteaIntegrationInput {
    is_active: Option<bool>,
    comment_task_link_on_gitea_issue: Option<bool>,
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
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    local_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProjectInput {
    name: String,
    icon: String,
    slug: String,
    description: String,
    is_public: bool,
    #[serde(default)]
    local_path: Option<String>,
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

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum OrchestratorStatus {
    Queued,
    Running,
    Waiting,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OrchestratorMessage {
    id: String,
    role: String,
    text: String,
    at: String,
}

#[derive(Debug, Clone)]
struct OrchestratorChild {
    id: String,
    orchestrator_id: Option<String>,
    task_id: Option<String>,
    prompt: String,
    cwd: PathBuf,
    model: Option<String>,
    network_access: bool,
    max_seconds: u64,
    attempt: u32,
    max_retries: u32,
    run_id: String,
    status: RunStatus,
    error: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone)]
struct OrchestratorRecord {
    id: String,
    parent_orchestrator_id: Option<String>,
    parent_child_id: Option<String>,
    depth: usize,
    workspace_id: String,
    project_id: String,
    credential: String,
    goal: String,
    cwd: PathBuf,
    model: Option<String>,
    network_access: bool,
    max_children: usize,
    max_retries: u32,
    max_seconds: u64,
    status: OrchestratorStatus,
    created_at: String,
    updated_at: String,
    active_turn_id: Option<String>,
    error: Option<String>,
    cancel_requested: bool,
    messages: Vec<OrchestratorMessage>,
    children: Vec<OrchestratorChild>,
}

#[derive(Default)]
struct OrchestratorState {
    records: HashMap<String, OrchestratorRecord>,
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
    local_path: Option<String>,
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

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct AgentEventResponse {
    at: String,
    #[serde(rename = "type")]
    event_type: String,
    text: String,
}

#[derive(Debug, Serialize, Clone)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOrchestratorInput {
    project_id: String,
    goal: String,
    cwd: Option<String>,
    model: Option<String>,
    network_access: Option<bool>,
    max_children: Option<usize>,
    max_retries: Option<u32>,
    max_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OrchestratorMessageInput {
    message: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct OrchestratorChildResponse {
    id: String,
    orchestrator_id: Option<String>,
    task_id: Option<String>,
    prompt: String,
    cwd: String,
    model: Option<String>,
    network_access: bool,
    max_seconds: u64,
    attempt: u32,
    max_retries: u32,
    run_id: String,
    status: RunStatus,
    error: Option<String>,
    created_at: String,
    updated_at: String,
    run: Option<AgentRunResponse>,
    orchestrator: Option<Box<OrchestratorResponse>>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct OrchestratorResponse {
    id: String,
    parent_orchestrator_id: Option<String>,
    parent_child_id: Option<String>,
    depth: usize,
    workspace_id: String,
    project_id: String,
    goal: String,
    cwd: String,
    model: Option<String>,
    network_access: bool,
    max_children: usize,
    max_retries: u32,
    max_seconds: u64,
    status: OrchestratorStatus,
    created_at: String,
    updated_at: String,
    active_turn_id: Option<String>,
    error: Option<String>,
    messages: Vec<OrchestratorMessage>,
    children: Vec<OrchestratorChildResponse>,
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

#[derive(Clone, Debug, Default, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    orchestrator_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<OrchestratorStatus>,
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

#[derive(Debug)]
struct IntegrationTaskData {
    id: String,
    title: String,
    number: Option<i32>,
    status: String,
    status_name: Option<String>,
    priority: Option<String>,
    project_id: String,
    project_name: String,
    workspace_id: String,
}

fn integration_event_key(event_type: &str) -> Option<&'static str> {
    match event_type {
        "TASK_CREATED" => Some("taskCreated"),
        "TASK_STATUS_CHANGED" | "TASK_UPDATED" => Some("taskStatusChanged"),
        "TASK_PRIORITY_CHANGED" => Some("taskPriorityChanged"),
        "TASK_TITLE_CHANGED" => Some("taskTitleChanged"),
        "TASK_DESCRIPTION_CHANGED" => Some("taskDescriptionChanged"),
        "TASK_COMMENT_CREATED" => Some("taskCommentCreated"),
        "TASK_DELETED" => Some("taskDeleted"),
        "TASK_MOVED" => Some("taskMoved"),
        "TASK_DUE_DATE_CHANGED" => Some("taskDueDateChanged"),
        "TASK_ASSIGNEE_CHANGED" => Some("taskAssigneeChanged"),
        _ => None,
    }
}

fn integration_event_name(event_type: &str) -> &'static str {
    match event_type {
        "TASK_CREATED" => "task.created",
        "TASK_STATUS_CHANGED" => "task.status_changed",
        "TASK_PRIORITY_CHANGED" => "task.priority_changed",
        "TASK_TITLE_CHANGED" => "task.title_changed",
        "TASK_DESCRIPTION_CHANGED" => "task.description_changed",
        "TASK_COMMENT_CREATED" => "comment.created",
        "TASK_DELETED" => "task.deleted",
        "TASK_MOVED" => "task.moved",
        "TASK_DUE_DATE_CHANGED" => "task.due_date_changed",
        "TASK_ASSIGNEE_CHANGED" => "task.assignee_changed",
        _ => "task.updated",
    }
}

fn integration_sentence(value: Option<&str>) -> String {
    value
        .unwrap_or("unknown")
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

fn sanitize_discord_content(value: &str) -> String {
    value
        .replace("@everyone", "@\u{200b}everyone")
        .replace("@here", "@\u{200b}here")
}

async fn integration_task_data(
    state: &AppState,
    task_id: &str,
) -> Result<Option<IntegrationTaskData>, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT t.id, t.title, t.number, t.status, t.priority,
                     c.name AS status_name, p.id AS project_id, p.name AS project_name,
                     w.id AS workspace_id
              FROM task t
              INNER JOIN project p ON p.id = t.project_id
              INNER JOIN workspace w ON w.id = p.workspace_id
              LEFT JOIN "column" c ON c.id = t.column_id AND c.project_id = p.id
              WHERE t.id = $1 LIMIT 1
            "#,
            &[&task_id],
        )
        .await
        .map_err(database_error)?;
    row.map(|row| {
        Ok(IntegrationTaskData {
            id: row_string(&row, "id")?,
            title: row_string(&row, "title")?,
            number: row_optional_i32(&row, "number")?,
            status: row_string(&row, "status")?,
            status_name: row_optional_string(&row, "status_name")?,
            priority: row_optional_string(&row, "priority")?,
            project_id: row_string(&row, "project_id")?,
            project_name: row_string(&row, "project_name")?,
            workspace_id: row_string(&row, "workspace_id")?,
        })
    })
    .transpose()
}

async fn post_integration_json(
    state: &AppState,
    url: &str,
    payload: Value,
    signature: Option<String>,
) -> Result<(), ApiError> {
    let body = serde_json::to_vec(&payload).map_err(database_error)?;
    let mut request = state
        .http
        .post(url)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(10));
    if let Some(signature) = signature {
        request = request.header("X-Kaneo-Signature", signature);
    }
    let response = request.body(body).send().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Integration delivery failed: {error}"),
        )
    })?;
    if !response.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Integration delivery returned {}", response.status()),
        ));
    }
    Ok(())
}

async fn dispatch_project_integrations(
    state: &AppState,
    event_type: &str,
    project_id: &str,
    task_id: &str,
    actor_id: &str,
) -> Result<(), ApiError> {
    let Some(event_key) = integration_event_key(event_type) else {
        return Ok(());
    };
    let Some(task) = integration_task_data(state, task_id).await? else {
        return Ok(());
    };
    if task.project_id != project_id {
        return Ok(());
    }
    let actor_name = state
        .database
        .client
        .query_opt(
            "SELECT name FROM \"user\" WHERE id = $1 LIMIT 1",
            &[&actor_id],
        )
        .await
        .map_err(database_error)?
        .and_then(|row| row.try_get::<_, String>("name").ok());
    let task_url = format!(
        "{}/dashboard/workspace/{}/project/{}/task/{}",
        state.client_url.trim_end_matches('/'),
        task.workspace_id,
        task.project_id,
        task.id
    );
    let integrations = state
        .database
        .client
        .query(
            "SELECT type, config, is_active FROM integration WHERE project_id = $1 AND is_active = TRUE",
            &[&project_id],
        )
        .await
        .map_err(database_error)?;
    let event_name = integration_event_name(event_type);
    let task_label = match task.number {
        Some(number) => format!("#{number} {}", task.title),
        None => task.title.clone(),
    };
    let actor = json!({ "id": actor_id, "name": actor_name });
    for integration in integrations {
        let integration_type = row_string(&integration, "type")?;
        let mut config = match serde_json::from_str::<Value>(&row_string(&integration, "config")?) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("integration: invalid {integration_type} config: {error}");
                continue;
            }
        };
        let Some(object) = config.as_object_mut() else {
            continue;
        };
        let enabled = object
            .get("events")
            .and_then(Value::as_object)
            .and_then(|events| events.get(event_key))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        let generic_payload = json!({
            "event": event_name,
            "timestamp": Utc::now().to_rfc3339(),
            "integration": { "type": integration_type },
            "project": {
                "id": task.project_id,
                "name": task.project_name,
                "workspaceId": task.workspace_id,
            },
            "task": {
                "id": task.id,
                "number": task.number,
                "title": task.title,
                "status": task.status,
                "statusName": task.status_name,
                "priority": task.priority,
                "url": task_url,
            },
            "actor": actor,
            "data": {},
        });
        let result = match integration_type.as_str() {
            "generic-webhook" => {
                let Some(webhook_url) = object.get("webhookUrl").and_then(Value::as_str) else {
                    continue;
                };
                if let Err(error) = validate_notification_destination(webhook_url).await {
                    Err(error)
                } else {
                    let signature = object.get("secret").and_then(Value::as_str).map(|secret| {
                        let body = generic_payload.to_string();
                        hex_digest(&hmac_sha256_bytes(secret.as_bytes(), body.as_bytes()))
                    });
                    post_integration_json(state, webhook_url, generic_payload, signature).await
                }
            }
            "slack" => {
                let Some(webhook_url) = object.get("webhookUrl").and_then(Value::as_str) else {
                    continue;
                };
                let text = format!(
                    "{}: *{}* in *{}* (status: {}, priority: {}) — {}",
                    integration_sentence(Some(event_key)),
                    task_label,
                    task.project_name,
                    integration_sentence(Some(&task.status)),
                    integration_sentence(task.priority.as_deref()),
                    task_url
                );
                post_integration_json(state, webhook_url, json!({ "text": text }), None).await
            }
            "discord" => {
                let Some(webhook_url) = object.get("webhookUrl").and_then(Value::as_str) else {
                    continue;
                };
                let title = sanitize_discord_content(&integration_sentence(Some(event_key)));
                let description = sanitize_discord_content(&format!(
                    "{} in {}. Status: {}. Priority: {}.",
                    task_label,
                    task.project_name,
                    integration_sentence(Some(&task.status)),
                    integration_sentence(task.priority.as_deref())
                ));
                post_integration_json(
                    state,
                    webhook_url,
                    json!({
                        "content": format!("{}: {}", title, sanitize_discord_content(&task_label)),
                        "embeds": [{
                            "title": title,
                            "description": description,
                            "url": task_url,
                            "color": 5793266,
                            "footer": { "text": format!("Triggered by {}", actor_name.as_deref().unwrap_or("Kaneo")) }
                        }]
                    }),
                    None,
                )
                .await
            }
            "telegram" => {
                let (Some(bot_token), Some(chat_id)) = (
                    object.get("botToken").and_then(Value::as_str),
                    object.get("chatId").and_then(Value::as_str),
                ) else {
                    continue;
                };
                let endpoint = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
                let text = format!(
                    "<b>{}</b>\n{}\n\n<b>Project:</b> {}\n<b>Status:</b> {}\n<b>Priority:</b> {}\n<b>Task:</b> {}",
                    event_key,
                    task_label,
                    task.project_name,
                    integration_sentence(Some(&task.status)),
                    integration_sentence(task.priority.as_deref()),
                    task_url
                );
                let mut payload = json!({
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": false,
                });
                if let Some(thread_id) = object.get("threadId").and_then(Value::as_i64) {
                    payload["message_thread_id"] = json!(thread_id);
                }
                post_integration_json(state, &endpoint, payload, None).await
            }
            _ => Ok(()),
        };
        if let Err(error) = result {
            eprintln!("integration {integration_type} delivery failed: {error}");
        }
    }
    Ok(())
}

fn publish_task_event(
    state: &AppState,
    event_type: &str,
    project_id: impl Into<String>,
    task_id: impl Into<String>,
    auth: &AuthContext,
    headers: &HeaderMap,
) {
    let project_id = project_id.into();
    let task_id = task_id.into();
    let _ = state.events.send(SocketEvent {
        event_type: match event_type {
            "TASK_STATUS_CHANGED"
            | "TASK_PRIORITY_CHANGED"
            | "TASK_TITLE_CHANGED"
            | "TASK_DESCRIPTION_CHANGED"
            | "TASK_COMMENT_CREATED"
            | "TASK_DUE_DATE_CHANGED"
            | "TASK_ASSIGNEE_CHANGED" => "TASK_UPDATED",
            _ => event_type,
        }
        .to_string(),
        project_id: Some(project_id.clone()),
        task_id: Some(task_id.clone()),
        source_task_id: None,
        target_task_id: None,
        initiator_id: socket_initiator(auth, headers),
        ..Default::default()
    });
    let dispatch_state = state.clone();
    let dispatch_event = event_type.to_string();
    let actor_id = auth.user_id.clone();
    tokio::spawn(async move {
        if let Err(error) = dispatch_project_integrations(
            &dispatch_state,
            &dispatch_event,
            &project_id,
            &task_id,
            &actor_id,
        )
        .await
        {
            eprintln!("integration dispatch failed: {error}");
        }
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
        ..Default::default()
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
        ..Default::default()
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

fn validate_project_local_path(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if value.chars().count() > 1_000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "localPath must be 1000 characters or fewer",
        ));
    }
    let path = FsPath::new(&value);
    if !path.is_absolute() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "localPath must be an absolute path",
        ));
    }
    if !path.is_dir() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Local project folder is not a directory: {value}"),
        ));
    }
    Ok(Some(value))
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

async fn project_local_path(
    database: &Database,
    project_id: &str,
) -> Result<Option<String>, ApiError> {
    database
        .client
        .query_opt(
            "SELECT local_path FROM project WHERE id = $1 LIMIT 1",
            &[&project_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_optional_string(&row, "local_path"))
        .transpose()
        .map(|value| value.flatten())
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

async fn openapi(State(state): State<AppState>) -> Json<Value> {
    let operation = |method: &str| {
        json!({
            method: {
                "responses": {
                    "200": { "description": "Successful response" },
                    "401": { "description": "Authentication required" },
                    "404": { "description": "Resource not found" }
                },
                "security": [{ "bearerAuth": [] }]
            }
        })
    };
    let mut paths = serde_json::Map::new();
    for (path, methods) in [
        ("/api/health", vec!["get"]),
        ("/api/config", vec!["get"]),
        ("/api/instance/status", vec!["get"]),
        ("/api/openapi", vec!["get"]),
        ("/api/public-project/{id}", vec!["get"]),
        ("/api/auth/get-session", vec!["get"]),
        ("/api/auth/sign-up/email", vec!["post"]),
        ("/api/auth/sign-in/email", vec!["post"]),
        ("/api/auth/sign-in/anonymous", vec!["post"]),
        ("/api/auth/sign-out", vec!["post"]),
        ("/api/auth/device/code", vec!["post"]),
        ("/api/auth/device/token", vec!["post"]),
        ("/api/auth/api-key/create", vec!["post"]),
        ("/api/auth/api-key/list", vec!["get"]),
        ("/api/auth/api-key/delete", vec!["post"]),
        ("/api/auth/organization/list", vec!["get"]),
        ("/api/auth/organization/create", vec!["post"]),
        ("/api/auth/organization/set-active", vec!["post"]),
        ("/api/auth/organization/update", vec!["post"]),
        ("/api/auth/organization/delete", vec!["post"]),
        ("/api/auth/organization/list-members", vec!["get"]),
        ("/api/auth/organization/get-active-member", vec!["get"]),
        ("/api/project", vec!["get", "post"]),
        ("/api/task/{id}", vec!["get", "post", "put", "delete"]),
        ("/api/task/tasks/{project_id}", vec!["get"]),
        ("/api/task/bulk", vec!["patch"]),
        ("/api/agent/runs", vec!["post"]),
        ("/api/agent/runs/{id}", vec!["get"]),
        ("/api/agent/runs/{id}/cancel", vec!["post"]),
        ("/api/agent/orchestrators", vec!["post"]),
        ("/api/agent/orchestrators/{id}", vec!["get"]),
        ("/api/agent/orchestrators/{id}/messages", vec!["post"]),
        ("/api/agent/orchestrators/{id}/cancel", vec!["post"]),
        ("/api/mcp", vec!["get", "post"]),
    ] {
        let mut item = serde_json::Map::new();
        for method in methods {
            if let Some(value) = operation(method).get(method) {
                item.insert(method.to_string(), value.clone());
            }
        }
        paths.insert(path.to_string(), Value::Object(item));
    }
    Json(json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Kaneo API",
            "version": "1.0.0",
            "description": "Kaneo project management and autonomous agent API"
        },
        "servers": [{ "url": state.api_base_url }],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Kaneo session token or API key"
                }
            }
        },
        "security": [{ "bearerAuth": [] }],
        "paths": paths
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

async fn rust_status(State(_state): State<AppState>) -> Json<Value> {
    Json(json!({
        "runtime": "rust",
        "database": "postgres",
        "legacyProxy": false,
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
                     p.local_path,
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
        "localPath": row_optional_string(&row, "local_path")?,
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
    let description = input
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let local_path = validate_project_local_path(input.local_path)?;
    let id = Uuid::new_v4().to_string();
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO project
                (id, workspace_id, slug, icon, name, description, local_path, is_public, last_task_number)
              VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, 0)
            "#,
            &[
                &id,
                &input.workspace_id,
                &input.slug,
                &input.icon,
                &input.name,
                &description,
                &local_path,
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
    let local_path = match input.local_path {
        Some(value) => validate_project_local_path(Some(value))?,
        None => project_local_path(&state.database, &id).await?,
    };
    let updated = state
        .database
        .client
        .execute(
            r#"
              UPDATE project
              SET name = $1, icon = $2, slug = $3, description = $4,
                  local_path = $5, is_public = $6
              WHERE id = $7 AND workspace_id = $8
            "#,
            &[
                &input.name,
                &input.icon,
                &input.slug,
                &input.description,
                &local_path,
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
        "TASK_STATUS_CHANGED",
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
        "TASK_TITLE_CHANGED",
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

const INTEGRATION_EVENT_KEYS: [&str; 6] = [
    "taskCreated",
    "taskStatusChanged",
    "taskPriorityChanged",
    "taskTitleChanged",
    "taskDescriptionChanged",
    "taskCommentCreated",
];

fn project_integration_defaults() -> serde_json::Map<String, Value> {
    [
        ("taskCreated", true),
        ("taskStatusChanged", true),
        ("taskPriorityChanged", false),
        ("taskTitleChanged", false),
        ("taskDescriptionChanged", false),
        ("taskCommentCreated", true),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), Value::Bool(value)))
    .collect()
}

fn project_integration_optional_text(input: &Value, key: &str) -> Result<Option<String>, ApiError> {
    match input.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("{key} must be a string"),
        )),
    }
}

fn project_integration_nullable_text(
    input: &Value,
    key: &str,
) -> Result<Option<Option<String>>, ApiError> {
    match input.get(key) {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(Value::String(value)) => Ok(Some(Some(value.clone()))),
        Some(_) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("{key} must be a string or null"),
        )),
    }
}

fn project_integration_optional_bool(input: &Value, key: &str) -> Result<Option<bool>, ApiError> {
    match input.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("{key} must be a boolean"),
        )),
    }
}

fn project_integration_optional_nullable_i32(
    input: &Value,
    key: &str,
) -> Result<Option<Option<i32>>, ApiError> {
    match input.get(key) {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(Value::Number(value)) => {
            let Some(value) = value.as_i64() else {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    format!("{key} must be an integer or null"),
                ));
            };
            let value = i32::try_from(value).map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    format!("{key} is outside the supported range"),
                )
            })?;
            Ok(Some(Some(value)))
        }
        Some(_) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("{key} must be an integer or null"),
        )),
    }
}

fn merge_project_integration_events(
    config: &mut Value,
    input: Option<&Value>,
) -> Result<(), ApiError> {
    let Some(input) = input else {
        return Ok(());
    };
    let Some(input) = input.as_object() else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "events must be an object",
        ));
    };
    let object = config.as_object_mut().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored integration config must be an object",
        )
    })?;
    let events = object
        .entry("events".to_string())
        .or_insert_with(|| Value::Object(project_integration_defaults()));
    let events = events.as_object_mut().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored integration events must be an object",
        )
    })?;
    for key in INTEGRATION_EVENT_KEYS {
        if let Some(value) = input.get(key) {
            if !value.is_boolean() {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    format!("events.{key} must be a boolean"),
                ));
            }
            events.insert(key.to_string(), value.clone());
        }
    }
    Ok(())
}

fn normalize_project_integration_events(config: &mut Value) -> Result<(), ApiError> {
    let object = config.as_object_mut().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored integration config must be an object",
        )
    })?;
    let mut events = project_integration_defaults();
    if let Some(existing) = object.get("events").and_then(Value::as_object) {
        for key in INTEGRATION_EVENT_KEYS {
            if let Some(value) = existing.get(key).filter(|value| value.is_boolean()) {
                events.insert(key.to_string(), value.clone());
            }
        }
    }
    object.insert("events".to_string(), Value::Object(events));
    Ok(())
}

fn validate_slack_webhook(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.scheme() != "https" || url.host_str() != Some("hooks.slack.com") {
        return false;
    }
    let parts = url
        .path()
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts.len() == 4
        && parts[0] == "services"
        && parts[1..]
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|value| value.is_ascii_alphanumeric()))
}

fn validate_discord_webhook(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.scheme() != "https" || !matches!(url.host_str(), Some("discord.com" | "discordapp.com"))
    {
        return false;
    }
    let parts = url
        .path()
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts.len() == 4 && parts[0] == "api" && parts[1] == "webhooks"
}

fn validate_telegram_bot_token(value: &str) -> bool {
    let Some((prefix, suffix)) = value.split_once(':') else {
        return false;
    };
    (8..=10).contains(&prefix.len())
        && prefix.chars().all(|value| value.is_ascii_digit())
        && suffix.len() == 35
        && suffix
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '_' | '-'))
}

fn mask_project_webhook_url(value: &str) -> String {
    let Ok(url) = Url::parse(value) else {
        return "Configured".to_string();
    };
    let parts = url
        .path()
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let Some(last) = parts.last() else {
        return "Configured".to_string();
    };
    let masked = if last.len() > 8 {
        format!("{}…{}", &last[..4], &last[last.len() - 4..])
    } else {
        "••••".to_string()
    };
    let origin = format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default()
    );
    let prefix = parts[..parts.len() - 1].join("/");
    if prefix.is_empty() {
        format!("{origin}/{masked}")
    } else {
        format!("{origin}/{prefix}/{masked}")
    }
}

fn mask_telegram_bot_token(value: &str) -> String {
    let Some((prefix, suffix)) = value.split_once(':') else {
        return "Configured".to_string();
    };
    if suffix.len() <= 8 {
        return format!("{prefix}:••••");
    }
    format!("{prefix}:{}…{}", &suffix[..4], &suffix[suffix.len() - 4..])
}

async fn project_integration_row(
    state: &AppState,
    project_id: &str,
    integration_type: &str,
) -> Result<Option<Row>, ApiError> {
    state
        .database
        .client
        .query_opt(
            r#"
              SELECT id, project_id, type, config, is_active,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM integration
              WHERE project_id = $1 AND type = $2
              LIMIT 1
            "#,
            &[&project_id, &integration_type],
        )
        .await
        .map_err(database_error)
}

fn project_integration_response(row: &Row, integration_type: &str) -> Result<Value, ApiError> {
    let mut config =
        serde_json::from_str::<Value>(&row_string(row, "config")?).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid {integration_type} integration config: {error}"),
            )
        })?;
    normalize_project_integration_events(&mut config)?;
    let object = config.as_object().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid {integration_type} integration config"),
        )
    })?;
    let events = object
        .get("events")
        .cloned()
        .unwrap_or_else(|| Value::Object(project_integration_defaults()));
    let is_active = row
        .try_get::<_, Option<bool>>("is_active")
        .map_err(database_error)?;
    let base = json!({
        "id": row_string(row, "id")?,
        "projectId": row_string(row, "project_id")?,
        "events": events,
        "isActive": is_active,
        "createdAt": row_string(row, "created_at")?,
        "updatedAt": row_string(row, "updated_at")?,
    });
    let webhook_url = object.get("webhookUrl").and_then(Value::as_str);
    let response = match integration_type {
        "slack" | "discord" => {
            let webhook_url = webhook_url.ok_or_else(|| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Invalid {integration_type} integration config"),
                )
            })?;
            let mut response = base;
            response["channelName"] = object
                .get("channelName")
                .and_then(Value::as_str)
                .map(Value::from)
                .unwrap_or(Value::Null);
            response["webhookConfigured"] = Value::Bool(!webhook_url.is_empty());
            response["maskedWebhookUrl"] = Value::String(mask_project_webhook_url(webhook_url));
            response
        }
        "telegram" => {
            let bot_token = object
                .get("botToken")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Invalid telegram integration config",
                    )
                })?;
            let chat_id = object
                .get("chatId")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Invalid telegram integration config",
                    )
                })?;
            let mut response = base;
            response["chatId"] = Value::String(chat_id.to_string());
            response["threadId"] = object.get("threadId").cloned().unwrap_or(Value::Null);
            response["chatLabel"] = object
                .get("chatLabel")
                .and_then(Value::as_str)
                .map(Value::from)
                .unwrap_or(Value::Null);
            response["botTokenConfigured"] = Value::Bool(!bot_token.is_empty());
            response["maskedBotToken"] = Value::String(mask_telegram_bot_token(bot_token));
            response
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unsupported project integration: {integration_type}"),
            ));
        }
    };
    Ok(response)
}

fn validate_project_integration_config(
    integration_type: &str,
    config: &Value,
) -> Result<(), ApiError> {
    let object = config.as_object().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Integration config must be an object",
        )
    })?;
    match integration_type {
        "slack" => {
            let value = object
                .get("webhookUrl")
                .and_then(Value::as_str)
                .filter(|value| validate_slack_webhook(value))
                .ok_or_else(|| {
                    ApiError::new(StatusCode::BAD_REQUEST, "Invalid Slack webhook URL")
                })?;
            if value.is_empty() {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Invalid Slack webhook URL",
                ));
            }
        }
        "discord" => {
            let value = object
                .get("webhookUrl")
                .and_then(Value::as_str)
                .filter(|value| validate_discord_webhook(value))
                .ok_or_else(|| {
                    ApiError::new(StatusCode::BAD_REQUEST, "Enter a valid Discord webhook URL")
                })?;
            if value.is_empty() {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Enter a valid Discord webhook URL",
                ));
            }
        }
        "telegram" => {
            let bot_token = object
                .get("botToken")
                .and_then(Value::as_str)
                .filter(|value| validate_telegram_bot_token(value))
                .ok_or_else(|| {
                    ApiError::new(StatusCode::BAD_REQUEST, "Enter a valid Telegram bot token")
                })?;
            if bot_token.is_empty() {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Enter a valid Telegram bot token",
                ));
            }
            if object
                .get("chatId")
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Chat ID is required",
                ));
            }
            if let Some(thread_id) = object.get("threadId") {
                if thread_id
                    .as_i64()
                    .is_none_or(|value| value < 1 || value > i32::MAX as i64)
                {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "threadId must be a positive integer",
                    ));
                }
            }
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unsupported project integration: {integration_type}"),
            ));
        }
    }
    Ok(())
}

async fn get_project_integration(
    state: &AppState,
    headers: &HeaderMap,
    project_id: &str,
    integration_type: &str,
) -> Result<Value, ApiError> {
    let _ = auth_for_project(state, headers, project_id).await?;
    Ok(project_integration_row(state, project_id, integration_type)
        .await?
        .as_ref()
        .map(|row| project_integration_response(row, integration_type))
        .transpose()?
        .unwrap_or(Value::Null))
}

async fn create_project_integration(
    state: &AppState,
    headers: &HeaderMap,
    project_id: &str,
    integration_type: &str,
    input: Value,
) -> Result<Value, ApiError> {
    let (auth, workspace_id) = auth_for_project(state, headers, project_id).await?;
    require_workspace_permission(state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let mut config = match integration_type {
        "slack" | "discord" => {
            let webhook_url = project_integration_required_string(&input, "webhookUrl")?;
            let mut config = json!({"webhookUrl": webhook_url});
            if let Some(channel_name) = project_integration_optional_text(&input, "channelName")? {
                config["channelName"] = json!(channel_name);
            }
            merge_project_integration_events(&mut config, input.get("events"))?;
            config
        }
        "telegram" => {
            let bot_token = project_integration_required_string(&input, "botToken")?;
            let chat_id = project_integration_required_string(&input, "chatId")?;
            let mut config = json!({"botToken": bot_token, "chatId": chat_id});
            if let Some(thread_id) = project_integration_optional_nullable_i32(&input, "threadId")?
            {
                if let Some(thread_id) = thread_id {
                    config["threadId"] = json!(thread_id);
                }
            }
            if let Some(chat_label) = project_integration_optional_text(&input, "chatLabel")? {
                config["chatLabel"] = json!(chat_label);
            }
            merge_project_integration_events(&mut config, input.get("events"))?;
            config
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unsupported project integration: {integration_type}"),
            ));
        }
    };
    normalize_project_integration_events(&mut config)?;
    validate_project_integration_config(integration_type, &config)?;
    let serialized = config.to_string();
    if let Some(existing) = project_integration_row(state, project_id, integration_type).await? {
        let id = row_string(&existing, "id")?;
        state
            .database
            .client
            .execute(
                "UPDATE integration SET config = $2, is_active = TRUE, updated_at = NOW() WHERE id = $1",
                &[&id, &serialized],
            )
            .await
            .map_err(database_error)?;
    } else {
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO integration
                    (id, project_id, type, config, is_active, created_at, updated_at)
                  VALUES ($1, $2, $3, $4, TRUE, NOW(), NOW())
                "#,
                &[
                    &Uuid::new_v4().to_string(),
                    &project_id,
                    &integration_type,
                    &serialized,
                ],
            )
            .await
            .map_err(database_error)?;
    }
    let row = project_integration_row(state, project_id, integration_type)
        .await?
        .ok_or_else(|| database_error("Project integration was not saved"))?;
    project_integration_response(&row, integration_type)
}

fn project_integration_required_string(input: &Value, key: &str) -> Result<String, ApiError> {
    input
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, format!("{key} is required")))
}

async fn update_project_integration(
    state: &AppState,
    headers: &HeaderMap,
    project_id: &str,
    integration_type: &str,
    input: Value,
) -> Result<Value, ApiError> {
    let (auth, workspace_id) = auth_for_project(state, headers, project_id).await?;
    require_workspace_permission(state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let existing = project_integration_row(state, project_id, integration_type)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                format!("{integration_type} integration not found"),
            )
        })?;
    let mut config =
        serde_json::from_str::<Value>(&row_string(&existing, "config")?).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid {integration_type} integration config: {error}"),
            )
        })?;
    normalize_project_integration_events(&mut config)?;
    match integration_type {
        "slack" | "discord" => {
            if let Some(webhook_url) = project_integration_optional_text(&input, "webhookUrl")? {
                if !webhook_url.trim().is_empty() {
                    config["webhookUrl"] = json!(webhook_url.trim());
                }
            }
            if let Some(channel_name) = project_integration_nullable_text(&input, "channelName")? {
                config["channelName"] = channel_name.map(Value::String).unwrap_or(Value::Null);
            }
        }
        "telegram" => {
            if let Some(bot_token) = project_integration_optional_text(&input, "botToken")? {
                config["botToken"] = json!(bot_token.trim());
            }
            if let Some(chat_id) = project_integration_optional_text(&input, "chatId")? {
                config["chatId"] = json!(chat_id.trim());
            }
            if let Some(thread_id) = project_integration_optional_nullable_i32(&input, "threadId")?
            {
                if let Some(thread_id) = thread_id {
                    config["threadId"] = Value::from(thread_id);
                } else if let Some(object) = config.as_object_mut() {
                    object.remove("threadId");
                }
            }
            if let Some(chat_label) = project_integration_nullable_text(&input, "chatLabel")? {
                if let Some(chat_label) = chat_label {
                    config["chatLabel"] = Value::String(chat_label);
                } else if let Some(object) = config.as_object_mut() {
                    object.remove("chatLabel");
                }
            }
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unsupported project integration: {integration_type}"),
            ));
        }
    }
    merge_project_integration_events(&mut config, input.get("events"))?;
    normalize_project_integration_events(&mut config)?;
    validate_project_integration_config(integration_type, &config)?;
    let is_active = project_integration_optional_bool(&input, "isActive")?
        .or_else(|| {
            existing
                .try_get::<_, Option<bool>>("is_active")
                .ok()
                .flatten()
        })
        .unwrap_or(true);
    let id = row_string(&existing, "id")?;
    let serialized = config.to_string();
    state
        .database
        .client
        .execute(
            "UPDATE integration SET config = $2, is_active = $3, updated_at = NOW() WHERE id = $1",
            &[&id, &serialized, &is_active],
        )
        .await
        .map_err(database_error)?;
    let row = project_integration_row(state, project_id, integration_type)
        .await?
        .ok_or_else(|| database_error("Project integration was not saved"))?;
    project_integration_response(&row, integration_type)
}

async fn delete_project_integration(
    state: &AppState,
    headers: &HeaderMap,
    project_id: &str,
    integration_type: &str,
) -> Result<Value, ApiError> {
    let (auth, workspace_id) = auth_for_project(state, headers, project_id).await?;
    require_workspace_permission(state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let existing = project_integration_row(state, project_id, integration_type)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                format!("{integration_type} integration not found"),
            )
        })?;
    let id = row_string(&existing, "id")?;
    state
        .database
        .client
        .execute("DELETE FROM integration WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?;
    Ok(json!({"success": true}))
}

async fn get_slack_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        get_project_integration(&state, &headers, &project_id, "slack").await?,
    ))
}

async fn create_slack_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        create_project_integration(&state, &headers, &project_id, "slack", input).await?,
    ))
}

async fn update_slack_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        update_project_integration(&state, &headers, &project_id, "slack", input).await?,
    ))
}

async fn delete_slack_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        delete_project_integration(&state, &headers, &project_id, "slack").await?,
    ))
}

async fn get_discord_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        get_project_integration(&state, &headers, &project_id, "discord").await?,
    ))
}

async fn create_discord_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        create_project_integration(&state, &headers, &project_id, "discord", input).await?,
    ))
}

async fn update_discord_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        update_project_integration(&state, &headers, &project_id, "discord", input).await?,
    ))
}

async fn delete_discord_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        delete_project_integration(&state, &headers, &project_id, "discord").await?,
    ))
}

async fn get_telegram_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        get_project_integration(&state, &headers, &project_id, "telegram").await?,
    ))
}

async fn create_telegram_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        create_project_integration(&state, &headers, &project_id, "telegram", input).await?,
    ))
}

async fn update_telegram_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        update_project_integration(&state, &headers, &project_id, "telegram", input).await?,
    ))
}

async fn delete_telegram_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        delete_project_integration(&state, &headers, &project_id, "telegram").await?,
    ))
}

async fn integration_row(
    state: &AppState,
    project_id: &str,
    integration_type: &str,
) -> Result<Option<Row>, ApiError> {
    state
        .database
        .client
        .query_opt(
            r#"
              SELECT id, project_id, config, COALESCE(is_active, TRUE) AS is_active,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM integration
              WHERE project_id = $1 AND type = $2
              LIMIT 1
            "#,
            &[&project_id, &integration_type],
        )
        .await
        .map_err(database_error)
}

async fn integration_row_by_id(
    state: &AppState,
    integration_id: &str,
    integration_type: &str,
) -> Result<Row, ApiError> {
    state
        .database
        .client
        .query_opt(
            "SELECT id, project_id, type, config, COALESCE(is_active, TRUE) AS is_active, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS updated_at FROM integration WHERE id = $1 AND type = $2 LIMIT 1",
            &[&integration_id, &integration_type],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Integration not found"))
}

async fn workspace_has_permission(
    state: &AppState,
    auth: &AuthContext,
    workspace_id: &str,
    resource: &str,
    action: &str,
) -> Result<bool, ApiError> {
    if auth.is_admin() {
        return Ok(true);
    }

    let Some(role) = state
        .database
        .client
        .query_opt(
            "SELECT role FROM workspace_member WHERE workspace_id = $1 AND user_id = $2 LIMIT 1",
            &[&workspace_id, &auth.user_id],
        )
        .await
        .map_err(database_error)?
        .and_then(|row| row.try_get::<_, String>("role").ok())
    else {
        return Ok(false);
    };

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

    Ok(granted
        .get(resource)
        .is_some_and(|actions| actions.iter().any(|value| value == action)))
}

fn integration_config(row: &Row) -> Result<Value, ApiError> {
    serde_json::from_str(&row_string(row, "config")?).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid integration config: {error}"),
        )
    })
}

fn github_integration_response(row: &Row) -> Result<Value, ApiError> {
    let config = integration_config(row)?;
    let object = config.as_object().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid GitHub integration config",
        )
    })?;
    let repository_owner = object
        .get("repositoryOwner")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "GitHub integration repository owner is missing",
            )
        })?;
    let repository_name = object
        .get("repositoryName")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "GitHub integration repository name is missing",
            )
        })?;
    Ok(json!({
        "id": row_string(row, "id")?,
        "projectId": row_string(row, "project_id")?,
        "repositoryOwner": repository_owner,
        "repositoryName": repository_name,
        "installationId": object.get("installationId").cloned().unwrap_or(Value::Null),
        "branchPattern": object.get("branchPattern").and_then(Value::as_str).unwrap_or("{slug}-{number}"),
        "commentTaskLinkOnGitHubIssue": object.get("commentTaskLinkOnGitHubIssue").and_then(Value::as_bool).unwrap_or(true),
        "isActive": row.try_get::<_, bool>("is_active").map_err(database_error)?,
        "createdAt": row_string(row, "created_at")?,
        "updatedAt": row_string(row, "updated_at")?,
    }))
}

fn github_app_configured() -> bool {
    env_present("GITHUB_WEBHOOK_SECRET")
        && env_present("GITHUB_APP_ID")
        && (env_present("GITHUB_PRIVATE_KEY") || env_present("GITHUB_PRIVATE_KEY_BASE64"))
}

fn github_default_config(repository_owner: &str, repository_name: &str) -> Value {
    json!({
        "repositoryOwner": repository_owner,
        "repositoryName": repository_name,
        "installationId": Value::Null,
        "branchPattern": "{slug}-{number}",
        "commentTaskLinkOnGitHubIssue": true,
        "statusTransitions": {
            "onBranchPush": "in-progress",
            "onPROpen": "in-review",
            "onPRMerge": "done"
        }
    })
}

async fn github_app_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authenticate(&state, &headers).await?;
    Ok(Json(json!({
        "appName": env::var("GITHUB_APP_NAME").ok().filter(|value| !value.is_empty()),
    })))
}

#[derive(Debug, Serialize)]
struct GithubJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

fn github_private_key() -> Result<String, ApiError> {
    if let Some(value) = env::var("GITHUB_PRIVATE_KEY_BASE64")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        return base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .map_err(|error| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Invalid GitHub private key encoding: {error}"),
                )
            })
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|error| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("GitHub private key is not UTF-8: {error}"),
                    )
                })
            });
    }
    let value = env::var("GITHUB_PRIVATE_KEY").unwrap_or_default();
    if value.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "GitHub App is not configured",
        ));
    }
    Ok(if value.contains("\\n") && !value.contains('\n') {
        value.replace("\\n", "\n")
    } else {
        value
    })
}

fn github_app_jwt() -> Result<String, ApiError> {
    let app_id = env::var("GITHUB_APP_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "GitHub App is not configured",
            )
        })?;
    let key = github_private_key()?;
    let now = Utc::now().timestamp();
    let claims = GithubJwtClaims {
        iat: now - 60,
        exp: now + 540,
        iss: app_id,
    };
    encode(
        &JwtHeader::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(key.as_bytes()).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid GitHub private key: {error}"),
            )
        })?,
    )
    .map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not sign GitHub App request: {error}"),
        )
    })
}

async fn github_request(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    token: &str,
    payload: Option<&Value>,
) -> Result<Value, ApiError> {
    let base_url =
        env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".to_string());
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let mut request = state
        .http
        .request(method, url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "kaneo-rust")
        .timeout(Duration::from_secs(15));
    if let Some(payload) = payload {
        request = request.json(payload);
    }
    let response = request.send().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Could not reach GitHub: {error}"),
        )
    })?;
    let status = StatusCode::from_u16(response.status().as_u16()).map_err(database_error)?;
    let body = response.text().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Could not read GitHub response: {error}"),
        )
    })?;
    if !status.is_success() {
        return Err(ApiError::new(status, format!("GitHub API error {status}")));
    }
    if body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&body).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("GitHub API returned invalid JSON: {error}"),
        )
    })
}

async fn github_installation_token(
    state: &AppState,
    installation_id: i64,
) -> Result<String, ApiError> {
    if let Some(token) = env::var("GITHUB_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(token);
    }
    let jwt = github_app_jwt()?;
    let response = github_request(
        state,
        reqwest::Method::POST,
        &format!("/app/installations/{installation_id}/access_tokens"),
        &jwt,
        None,
    )
    .await?;
    response
        .get("token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "GitHub did not return an installation token",
            )
        })
}

fn github_repo_json(value: &Value, installation_id: Option<i64>) -> Value {
    let owner = value
        .get("owner")
        .and_then(|owner| owner.get("login"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    json!({
        "id": value.get("id").and_then(Value::as_i64).unwrap_or_default(),
        "name": value.get("name").and_then(Value::as_str).unwrap_or_default(),
        "full_name": value.get("full_name").and_then(Value::as_str).unwrap_or_default(),
        "owner": { "login": owner },
        "private": value.get("private").and_then(Value::as_bool).unwrap_or(false),
        "html_url": value.get("html_url").and_then(Value::as_str).unwrap_or_default(),
        "description": value.get("description").cloned().unwrap_or(Value::Null),
        "permissions": value.get("permissions").cloned().unwrap_or(Value::Null),
        "updated_at": value.get("updated_at").cloned().unwrap_or(Value::Null),
        "installation_id": installation_id,
    })
}

async fn list_github_repositories(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authenticate(&state, &headers).await?;
    let jwt = github_app_jwt()?;
    let installations = github_request(
        &state,
        reqwest::Method::GET,
        "/app/installations?per_page=100",
        &jwt,
        None,
    )
    .await?;
    let mut repositories = Vec::new();
    let mut installation_records = Vec::new();
    for installation in installations.as_array().into_iter().flatten() {
        let installation_id = installation
            .get("id")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        if installation_id == 0 {
            continue;
        }
        let account = installation.get("account").map(|account| {
            json!({
                "login": account.get("login").and_then(Value::as_str).unwrap_or_default(),
                "type": account.get("type").and_then(Value::as_str).unwrap_or_default(),
            })
        });
        match github_installation_token(&state, installation_id).await {
            Ok(token) => {
                let page = github_request(
                    &state,
                    reqwest::Method::GET,
                    "/installation/repositories?per_page=100",
                    &token,
                    None,
                )
                .await
                .unwrap_or_else(|_| json!({ "repositories": [] }));
                let names = page
                    .get("repositories")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|repo| {
                        repo.get("full_name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string()
                    })
                    .collect::<Vec<_>>();
                installation_records.push(json!({
                    "id": installation_id,
                    "account": account,
                    "repositories": names,
                }));
                repositories.extend(
                    page.get("repositories")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .map(|repo| github_repo_json(repo, Some(installation_id))),
                );
            }
            Err(_) => installation_records.push(json!({
                "id": installation_id,
                "account": account,
                "repositories": [],
            })),
        }
    }
    repositories.sort_by_key(|repo| {
        std::cmp::Reverse(
            repo.get("updated_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )
    });
    repositories.dedup_by_key(|repo| repo.get("id").cloned());
    let total = repositories.len();
    Ok(Json(json!({
        "repositories": repositories,
        "installations": installation_records,
        "total": total,
    })))
}

async fn verify_github_installation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<VerifyGithubInput>,
) -> Result<Json<Value>, ApiError> {
    authenticate(&state, &headers).await?;
    let owner = input.repository_owner.trim();
    let repository = input.repository_name.trim();
    if owner.is_empty() || repository.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "repositoryOwner and repositoryName are required",
        ));
    }
    let jwt = github_app_jwt()?;
    let repo_path = format!(
        "/repos/{}/{}",
        url::form_urlencoded::byte_serialize(owner.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(repository.as_bytes()).collect::<String>(),
    );
    let repo = github_request(&state, reqwest::Method::GET, &repo_path, &jwt, None).await?;
    let installation = match github_request(
        &state,
        reqwest::Method::GET,
        &format!("{repo_path}/installation"),
        &jwt,
        None,
    )
    .await
    {
        Ok(value) => value,
        Err(error) if error.status == StatusCode::NOT_FOUND => {
            return Ok(Json(json!({
                "isInstalled": false,
                "installationId": Value::Null,
                "repositoryExists": true,
                "repositoryPrivate": repo.get("private").and_then(Value::as_bool),
                "permissions": Value::Null,
                "hasRequiredPermissions": false,
                "missingPermissions": ["issues"],
                "message": "Repository exists but GitHub App is not installed",
                "settingsUrl": env::var("GITHUB_APP_NAME").ok().map(|name| format!("https://github.com/apps/{name}")),
            })));
        }
        Err(error) => return Err(error),
    };
    let installation_id = installation
        .get("id")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let permissions = installation
        .get("permissions")
        .cloned()
        .unwrap_or(Value::Null);
    let permission = permissions
        .get("issues")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let has_permissions = matches!(permission, "write" | "admin");
    Ok(Json(json!({
        "isInstalled": true,
        "installationId": installation_id,
        "repositoryExists": true,
        "repositoryPrivate": repo.get("private").and_then(Value::as_bool),
        "permissions": permissions,
        "hasRequiredPermissions": has_permissions,
        "missingPermissions": if has_permissions { Vec::<String>::new() } else { vec!["issues".to_string()] },
        "message": if has_permissions { "GitHub App is properly installed and has all required permissions" } else { "GitHub App is installed but missing required permissions: issues" },
        "settingsUrl": format!("https://github.com/settings/installations/{installation_id}"),
        "installationUrl": env::var("GITHUB_APP_NAME").ok().map(|name| format!("https://github.com/apps/{name}/installations/new/permissions?target_id={}", repo.get("id").and_then(Value::as_i64).unwrap_or_default())),
    })))
}

async fn import_github_comments(
    state: &AppState,
    token: &str,
    owner: &str,
    repository: &str,
    issue_number: i64,
    task_id: &str,
) -> Result<(), ApiError> {
    let owner = url::form_urlencoded::byte_serialize(owner.as_bytes()).collect::<String>();
    let repository =
        url::form_urlencoded::byte_serialize(repository.as_bytes()).collect::<String>();
    for page in 1..=50 {
        let comments = github_request(
            state,
            reqwest::Method::GET,
            &format!(
                "/repos/{owner}/{repository}/issues/{issue_number}/comments?per_page=100&page={page}"
            ),
            token,
            None,
        )
        .await?;
        let Some(comments) = comments.as_array() else {
            break;
        };
        if comments.is_empty() {
            break;
        }
        for comment in comments {
            let username = comment
                .get("user")
                .and_then(|value| value.get("login"))
                .and_then(Value::as_str)
                .unwrap_or("Unknown");
            if username.ends_with("[bot]") {
                continue;
            }
            let url = comment
                .get("html_url")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if url.is_empty() {
                continue;
            }
            let content = comment
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let avatar = comment
                .get("user")
                .and_then(|value| value.get("avatar_url"))
                .and_then(Value::as_str);
            state
                .database
                .client
                .execute(
                    "INSERT INTO activity (id, task_id, type, content, external_user_name, external_user_avatar, external_source, external_url, created_at, updated_at) VALUES ($1, $2, 'comment', $3, $4, $5, 'github', $6, NOW(), NOW()) ON CONFLICT (task_id, external_source, external_url) DO NOTHING",
                    &[&Uuid::new_v4().to_string(), &task_id, &content, &username, &avatar, &url],
                )
                .await
                .map_err(database_error)?;
        }
        if comments.len() < 100 {
            break;
        }
    }
    Ok(())
}

async fn import_github_issue(
    state: &AppState,
    auth: &AuthContext,
    headers: &HeaderMap,
    integration_id: &str,
    project_id: &str,
    workspace_id: &str,
    config: &Value,
    token: &str,
    issue: &Value,
) -> Result<&'static str, ApiError> {
    let number = issue
        .get("number")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_GATEWAY, "GitHub issue has no number"))?;
    let number_string = number.to_string();
    let title = issue
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Untitled issue")
        .to_string();
    let description = issue
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let (status, priority) =
        imported_issue_status_priority(issue.get("labels").unwrap_or(&Value::Null));
    let existing = imported_external_link(state, integration_id, "issue", &number_string).await?;
    let was_existing = existing.is_some();
    let task_id = if let Some((link_id, task_id)) = existing {
        state
            .database
            .client
            .execute(
                "UPDATE task SET title = $1, description = $2, status = $3, priority = COALESCE($4, priority), updated_at = NOW() WHERE id = $5",
                &[&title, &description, &status, &priority, &task_id],
            )
            .await
            .map_err(database_error)?;
        let url = issue
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let metadata = serde_json::to_string(&json!({
            "state": issue.get("state").and_then(Value::as_str),
            "createdFrom": "github-import",
        }))
        .map_err(database_error)?;
        state
            .database
            .client
            .execute(
                "UPDATE external_link SET url = $1, title = $2, metadata = $3, updated_at = NOW() WHERE id = $4",
                &[&url, &title, &metadata, &link_id],
            )
            .await
            .map_err(database_error)?;
        task_id
    } else {
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
        let column_id = column_for_status(&state.database, project_id, &status).await?;
        let position: i32 = state
            .database
            .client
            .query_one(
                "SELECT COALESCE(MAX(position), 0) + 1 AS position FROM task WHERE project_id = $1 AND status = $2",
                &[&project_id, &status],
            )
            .await
            .map_err(database_error)?
            .try_get("position")
            .map_err(database_error)?;
        let task_id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                "INSERT INTO task (id, project_id, position, number, title, description, status, column_id, priority, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())",
                &[&task_id, &project_id, &position, &number, &title, &description, &status, &column_id, &priority],
            )
            .await
            .map_err(database_error)?;
        let url = issue
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let metadata = serde_json::to_string(&json!({
            "state": issue.get("state").and_then(Value::as_str),
            "createdFrom": "github-import",
            "author": issue
                .get("user")
                .and_then(|value| value.get("login"))
                .and_then(Value::as_str),
        }))
        .map_err(database_error)?;
        state
            .database
            .client
            .execute(
                "INSERT INTO external_link (id, task_id, integration_id, resource_type, external_id, url, title, metadata, created_at, updated_at) VALUES ($1, $2, $3, 'issue', $4, $5, $6, $7, NOW(), NOW())",
                &[&Uuid::new_v4().to_string(), &task_id, &integration_id, &number_string, &url, &title, &metadata],
            )
            .await
            .map_err(database_error)?;
        let task = task_by_id(&state.database, &task_id).await?;
        publish_task_event(
            state,
            "TASK_CREATED",
            task.project_id,
            task.id,
            auth,
            headers,
        );
        task_id
    };
    import_external_labels(
        state,
        issue.get("labels").unwrap_or(&Value::Null),
        &task_id,
        workspace_id,
    )
    .await?;
    let owner = config
        .get("repositoryOwner")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let repository = config
        .get("repositoryName")
        .and_then(Value::as_str)
        .unwrap_or_default();
    import_github_comments(state, token, owner, repository, number, &task_id).await?;
    Ok(if was_existing { "updated" } else { "imported" })
}

async fn import_github_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ImportIntegrationInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &input.project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "task", "create").await?;
    let integration = integration_row(&state, &input.project_id, "github")
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "GitHub integration not found"))?;
    if !integration
        .try_get::<_, bool>("is_active")
        .map_err(database_error)?
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "GitHub integration is not active",
        ));
    }
    let integration_id = row_string(&integration, "id")?;
    let config = integration_config(&integration)?;
    let installation_id = config
        .get("installationId")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "GitHub installation ID not configured",
            )
        })?;
    let token = github_installation_token(&state, installation_id).await?;
    let owner = config
        .get("repositoryOwner")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "GitHub repository owner is missing",
            )
        })?;
    let repository = config
        .get("repositoryName")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(StatusCode::BAD_REQUEST, "GitHub repository name is missing")
        })?;
    let owner = url::form_urlencoded::byte_serialize(owner.as_bytes()).collect::<String>();
    let repository =
        url::form_urlencoded::byte_serialize(repository.as_bytes()).collect::<String>();
    let mut imported = 0;
    let mut updated = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();
    for page in 1..=50 {
        let issues = github_request(
            &state,
            reqwest::Method::GET,
            &format!("/repos/{owner}/{repository}/issues?state=open&per_page=100&page={page}"),
            &token,
            None,
        )
        .await?;
        let Some(issues) = issues.as_array() else {
            break;
        };
        if issues.is_empty() {
            break;
        }
        for issue in issues {
            if issue.get("pull_request").is_some() {
                skipped += 1;
                continue;
            }
            match import_github_issue(
                &state,
                &auth,
                &headers,
                &integration_id,
                &input.project_id,
                &workspace_id,
                &config,
                &token,
                issue,
            )
            .await
            {
                Ok("imported") => imported += 1,
                Ok("updated") => updated += 1,
                Ok(_) => skipped += 1,
                Err(error) => errors.push(format!(
                    "Issue #{}: {}",
                    issue
                        .get("number")
                        .and_then(Value::as_i64)
                        .unwrap_or_default(),
                    error.message
                )),
            }
        }
        if issues.len() < 100 {
            break;
        }
    }
    Ok(Json(json!({
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": if errors.is_empty() { Value::Null } else { json!(errors) },
    })))
}

async fn github_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Missing signature"))?;
    let secret = env::var("GITHUB_WEBHOOK_SECRET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(StatusCode::BAD_REQUEST, "GitHub integration not configured")
        })?;
    if !verify_hmac_hex(&secret, &body, signature) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid webhook signature",
        ));
    }
    let event = headers
        .get("x-github-event")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Missing event name"))?;
    let payload: Value = serde_json::from_slice(&body).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid JSON payload: {error}"),
        )
    })?;
    let installation_id = payload
        .get("installation")
        .and_then(|value| value.get("id"))
        .and_then(Value::as_i64);
    let repository = payload.get("repository");
    let rows = state
        .database
        .client
        .query(
            "SELECT id, project_id, config FROM integration WHERE type = 'github' AND COALESCE(is_active, TRUE) = TRUE",
            &[],
        )
        .await
        .map_err(database_error)?;
    for row in rows {
        let config = integration_config(&row)?;
        let config_installation_id = config.get("installationId").and_then(Value::as_i64);
        let config_owner = config
            .get("repositoryOwner")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let config_repository = config
            .get("repositoryName")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let payload_owner = repository
            .and_then(|value| value.get("owner"))
            .and_then(|value| value.get("login"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let payload_repository = repository
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if installation_id.is_some_and(|value| config_installation_id != Some(value))
            && (payload_owner != config_owner || payload_repository != config_repository)
        {
            continue;
        }
        let integration_id = row_string(&row, "id")?;
        let issue = payload.get("issue").unwrap_or(&Value::Null);
        if matches!(event, "issues") {
            if let Some(number) = issue.get("number").and_then(Value::as_i64) {
                if let Some((_, task_id)) =
                    imported_external_link(&state, &integration_id, "issue", &number.to_string())
                        .await?
                {
                    let action = payload
                        .get("action")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let (mut status, priority) =
                        imported_issue_status_priority(issue.get("labels").unwrap_or(&Value::Null));
                    if action == "closed" {
                        status = "done".to_string();
                    }
                    let column_id = column_for_status(
                        &state.database,
                        &row_string(&row, "project_id")?,
                        &status,
                    )
                    .await
                    .ok()
                    .flatten();
                    let title = issue.get("title").and_then(Value::as_str);
                    let description = issue.get("body").and_then(Value::as_str);
                    state
                        .database
                        .client
                        .execute(
                            "UPDATE task SET title = COALESCE($1, title), description = COALESCE($2, description), status = $3, column_id = $4, priority = COALESCE($5, priority), updated_at = NOW() WHERE id = $6",
                            &[&title, &description, &status, &column_id, &priority, &task_id],
                        )
                        .await
                        .map_err(database_error)?;
                }
            }
        } else if matches!(event, "issue_comment")
            && payload.get("action").and_then(Value::as_str) == Some("created")
        {
            if let Some(number) = issue.get("number").and_then(Value::as_i64) {
                if let Some((_, task_id)) =
                    imported_external_link(&state, &integration_id, "issue", &number.to_string())
                        .await?
                {
                    let comment = payload.get("comment").unwrap_or(&Value::Null);
                    let url = comment
                        .get("html_url")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !url.is_empty() {
                        let username = comment
                            .get("user")
                            .and_then(|value| value.get("login"))
                            .and_then(Value::as_str)
                            .unwrap_or("github-webhook");
                        let content = comment
                            .get("body")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        state
                            .database
                            .client
                            .execute(
                                "INSERT INTO activity (id, task_id, type, content, external_user_name, external_source, external_url, created_at, updated_at) VALUES ($1, $2, 'comment', $3, $4, 'github', $5, NOW(), NOW()) ON CONFLICT (task_id, external_source, external_url) DO NOTHING",
                                &[&Uuid::new_v4().to_string(), &task_id, &content, &username, &url],
                            )
                            .await
                            .map_err(database_error)?;
                    }
                }
            }
        } else if matches!(event, "pull_request") {
            let pull_request = payload.get("pull_request").unwrap_or(&Value::Null);
            if let Some(number) = pull_request.get("number").and_then(Value::as_i64) {
                if let Some((_, task_id)) = imported_external_link(
                    &state,
                    &integration_id,
                    "pull_request",
                    &number.to_string(),
                )
                .await?
                {
                    let action = payload
                        .get("action")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let status_key = if action == "closed"
                        && pull_request.get("merged").and_then(Value::as_bool) == Some(true)
                    {
                        "onPRMerge"
                    } else {
                        "onPROpen"
                    };
                    if let Some(status) = config
                        .get("statusTransitions")
                        .and_then(|value| value.get(status_key))
                        .and_then(Value::as_str)
                    {
                        let project_id = row_string(&row, "project_id")?;
                        let column_id = column_for_status(&state.database, &project_id, status)
                            .await
                            .ok()
                            .flatten();
                        state
                            .database
                            .client
                            .execute(
                                "UPDATE task SET status = $1, column_id = $2, updated_at = NOW() WHERE id = $3",
                                &[&status, &column_id, &task_id],
                            )
                            .await
                            .map_err(database_error)?;
                    }
                }
            }
        }
    }
    Ok(Json(json!({ "status": "success" })))
}

async fn get_github_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (_, _) = auth_for_project(&state, &headers, &project_id).await?;
    let Some(row) = integration_row(&state, &project_id, "github").await? else {
        return Ok(Json(Value::Null));
    };
    Ok(Json(github_integration_response(&row)?))
}

async fn create_github_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<CreateGithubIntegrationInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let owner = input.repository_owner.trim();
    let repository = input.repository_name.trim();
    if owner.is_empty() || repository.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "repositoryOwner and repositoryName are required",
        ));
    }
    if !github_app_configured() {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "GitHub app not configured",
        ));
    }

    for row in state
        .database
        .client
        .query(
            "SELECT project_id, config FROM integration WHERE type = 'github'",
            &[],
        )
        .await
        .map_err(database_error)?
    {
        if row_string(&row, "project_id")? == project_id {
            continue;
        }
        let config = integration_config(&row)?;
        if config.get("repositoryOwner").and_then(Value::as_str) == Some(owner)
            && config.get("repositoryName").and_then(Value::as_str) == Some(repository)
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("Repository {owner}/{repository} is already linked to another project"),
            ));
        }
    }

    let config =
        serde_json::to_string(&github_default_config(owner, repository)).map_err(database_error)?;
    if let Some(existing) = integration_row(&state, &project_id, "github").await? {
        let id = row_string(&existing, "id")?;
        let row = state
            .database
            .client
            .query_one(
                "UPDATE integration SET config = $2, is_active = TRUE, updated_at = NOW() WHERE id = $1 RETURNING id, project_id, config, COALESCE(is_active, TRUE) AS is_active, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS updated_at",
                &[&id, &config],
            )
            .await
            .map_err(database_error)?;
        return Ok(Json(github_integration_response(&row)?));
    }

    let id = Uuid::new_v4().simple().to_string();
    let row = state
        .database
        .client
        .query_one(
            "INSERT INTO integration (id, project_id, type, config, is_active) VALUES ($1, $2, 'github', $3, TRUE) RETURNING id, project_id, config, COALESCE(is_active, TRUE) AS is_active, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS updated_at",
            &[&id, &project_id, &config],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(github_integration_response(&row)?))
}

async fn update_github_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<UpdateGithubIntegrationInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let Some(existing) = integration_row(&state, &project_id, "github").await? else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Integration not found",
        ));
    };
    let mut config = integration_config(&existing)?;
    if let Some(comment_link) = input.comment_task_link_on_github_issue {
        config["commentTaskLinkOnGitHubIssue"] = Value::Bool(comment_link);
    }
    let serialized = serde_json::to_string(&config).map_err(database_error)?;
    let id = row_string(&existing, "id")?;
    let is_active = input.is_active.unwrap_or(
        existing
            .try_get::<_, bool>("is_active")
            .map_err(database_error)?,
    );
    let row = state
        .database
        .client
        .query_one(
            "UPDATE integration SET config = $2, is_active = $3, updated_at = NOW() WHERE id = $1 RETURNING id, project_id, config, COALESCE(is_active, TRUE) AS is_active, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS updated_at",
            &[&id, &serialized, &is_active],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(github_integration_response(&row)?))
}

async fn delete_github_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let Some(row) = integration_row(&state, &project_id, "github").await? else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "GitHub integration not found",
        ));
    };
    let id = row_string(&row, "id")?;
    state
        .database
        .client
        .execute("DELETE FROM integration WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?;
    Ok(Json(json!({
        "success": true,
        "message": "GitHub integration deleted"
    })))
}

fn normalize_gitea_base_url(value: &str) -> Result<String, ApiError> {
    let normalized = value.trim().trim_end_matches('/').to_string();
    let url = Url::parse(&normalized).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "A valid Gitea base URL is required",
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "A valid Gitea base URL is required",
        ));
    }
    Ok(normalized)
}

fn gitea_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

async fn gitea_json(
    state: &AppState,
    base_url: &str,
    access_token: &str,
    path: &str,
) -> Result<Value, ApiError> {
    gitea_request(
        state,
        reqwest::Method::GET,
        base_url,
        access_token,
        path,
        None,
    )
    .await
}

async fn gitea_request(
    state: &AppState,
    method: reqwest::Method,
    base_url: &str,
    access_token: &str,
    path: &str,
    payload: Option<&Value>,
) -> Result<Value, ApiError> {
    let url = format!("{}/api/v1{}", base_url.trim_end_matches('/'), path);
    let mut request = state
        .http
        .request(method, url)
        .header("Authorization", format!("token {access_token}"))
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(10));
    if let Some(payload) = payload {
        request = request.json(payload);
    }
    let response = request.send().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Could not reach Gitea: {error}"),
        )
    })?;
    let status = StatusCode::from_u16(response.status().as_u16()).map_err(database_error)?;
    let body = response.text().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Could not read Gitea response: {error}"),
        )
    })?;
    if !status.is_success() {
        return Err(ApiError::new(status, format!("Gitea API error {status}")));
    }
    if body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&body).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Gitea API returned invalid JSON: {error}"),
        )
    })
}

fn gitea_repo_json(value: &Value) -> Value {
    let owner = value
        .get("owner")
        .and_then(|owner| owner.get("login").or_else(|| owner.get("username")))
        .and_then(Value::as_str)
        .unwrap_or_default();
    json!({
        "id": value.get("id").and_then(Value::as_i64).unwrap_or_default(),
        "name": value.get("name").and_then(Value::as_str).unwrap_or_default(),
        "full_name": value.get("full_name").and_then(Value::as_str).unwrap_or_default(),
        "owner": { "login": owner },
        "private": value.get("private").and_then(Value::as_bool).unwrap_or(false),
        "html_url": value.get("html_url").and_then(Value::as_str).unwrap_or_default(),
    })
}

fn mask_integration_secret(value: &str) -> String {
    if value.chars().count() <= 8 {
        return "••••••••".to_string();
    }
    let prefix: String = value.chars().take(4).collect();
    let suffix: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{prefix}••••••{suffix}")
}

fn gitea_integration_response(
    row: &Row,
    include_webhook_secret: bool,
    api_base_url: &str,
) -> Result<Value, ApiError> {
    let config = integration_config(row)?;
    let object = config.as_object().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid Gitea integration config",
        )
    })?;
    let base_url = object
        .get("baseUrl")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let access_token = object
        .get("accessToken")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let integration_id = row_string(row, "id")?;
    Ok(json!({
        "id": integration_id,
        "projectId": row_string(row, "project_id")?,
        "baseUrl": base_url,
        "repositoryOwner": object.get("repositoryOwner").and_then(Value::as_str).unwrap_or_default(),
        "repositoryName": object.get("repositoryName").and_then(Value::as_str).unwrap_or_default(),
        "maskedAccessToken": mask_integration_secret(access_token),
        "webhookUrl": format!("{}/api/gitea-integration/webhook/{integration_id}", api_base_url.trim_end_matches('/')),
        "webhookSecret": if include_webhook_secret { object.get("webhookSecret").and_then(Value::as_str).unwrap_or_default() } else { "" },
        "branchPattern": object.get("branchPattern").and_then(Value::as_str).unwrap_or("{slug}-{number}"),
        "commentTaskLinkOnGiteaIssue": object.get("commentTaskLinkOnGiteaIssue").and_then(Value::as_bool).unwrap_or(true),
        "isActive": row.try_get::<_, bool>("is_active").map_err(database_error)?,
        "createdAt": row_string(row, "created_at")?,
        "updatedAt": row_string(row, "updated_at")?,
    }))
}

async fn list_gitea_repositories(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<GiteaRepositoriesInput>,
) -> Result<Json<Value>, ApiError> {
    authenticate(&state, &headers).await?;
    let base_url = normalize_gitea_base_url(&input.base_url)?;
    let access_token = input.access_token.trim();
    if access_token.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "accessToken is required",
        ));
    }

    let mut repositories = Vec::new();
    for page in 1..=50 {
        let path = format!("/user/repos?page={page}&limit=50");
        let batch = gitea_json(&state, &base_url, access_token, &path).await?;
        let Some(items) = batch.as_array() else {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "Gitea repositories response was not an array",
            ));
        };
        if items.is_empty() {
            break;
        }
        repositories.extend(items.iter().map(gitea_repo_json));
        if items.len() < 50 {
            break;
        }
    }
    Ok(Json(json!({ "repositories": repositories })))
}

async fn verify_gitea_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<VerifyGiteaInput>,
) -> Result<Json<Value>, ApiError> {
    authenticate(&state, &headers).await?;
    let base_url = normalize_gitea_base_url(&input.base_url)?;
    let access_token = input.access_token.trim();
    if access_token.is_empty()
        || input.repository_owner.trim().is_empty()
        || input.repository_name.trim().is_empty()
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "baseUrl, accessToken, repositoryOwner, and repositoryName are required",
        ));
    }

    if let Err(error) = gitea_json(&state, &base_url, access_token, "/user").await {
        if error.status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "Invalid Gitea token or unauthorized.",
            ));
        }
        return Err(error);
    }

    let repository_path = format!(
        "/repos/{}/{}",
        gitea_path_segment(input.repository_owner.trim()),
        gitea_path_segment(input.repository_name.trim())
    );
    let repository = match gitea_json(&state, &base_url, access_token, &repository_path).await {
        Ok(repository) => repository,
        Err(error) if error.status == StatusCode::NOT_FOUND => {
            return Ok(Json(json!({
                "isInstalled": false,
                "hasRequiredPermissions": false,
                "repositoryExists": false,
                "repositoryPrivate": Value::Null,
                "missingPermissions": [],
                "message": "Repository not found or not accessible with this token."
            })));
        }
        Err(error) => return Err(error),
    };
    let permissions = repository.get("permissions");
    let has_issues_write = permissions
        .and_then(|value| value.get("admin").or_else(|| value.get("push")))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(Json(json!({
        "isInstalled": true,
        "hasRequiredPermissions": has_issues_write,
        "repositoryExists": true,
        "repositoryPrivate": repository.get("private").and_then(Value::as_bool),
        "missingPermissions": if has_issues_write { Vec::<String>::new() } else { vec!["issues (write)".to_string()] },
        "message": if has_issues_write { "Token can access the repository." } else { "Token may not have sufficient permissions to manage issues." }
    })))
}

async fn get_gitea_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    let Some(row) = integration_row(&state, &project_id, "gitea").await? else {
        return Ok(Json(Value::Null));
    };
    let include_secret =
        workspace_has_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
            .await?;
    Ok(Json(gitea_integration_response(
        &row,
        include_secret,
        &state.api_base_url,
    )?))
}

async fn create_gitea_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<CreateGiteaIntegrationInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let base_url = normalize_gitea_base_url(&input.base_url)?;
    let owner = input.repository_owner.trim();
    let repository_name = input.repository_name.trim();
    if owner.is_empty() || repository_name.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "repositoryOwner and repositoryName are required",
        ));
    }

    let existing = integration_row(&state, &project_id, "gitea").await?;
    let previous_config = existing
        .as_ref()
        .and_then(|row| integration_config(row).ok());
    let access_token = input
        .access_token
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    let access_token = if access_token.is_empty() {
        previous_config
            .as_ref()
            .and_then(|config| config.get("accessToken"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    } else {
        access_token
    };
    if access_token.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Personal access token is required",
        ));
    }

    gitea_json(&state, &base_url, &access_token, "/user")
        .await
        .map_err(|error| {
            if error.status == StatusCode::UNAUTHORIZED {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "Invalid Gitea token or unauthorized.",
                )
            } else {
                error
            }
        })?;
    let repository_path = format!(
        "/repos/{}/{}",
        gitea_path_segment(owner),
        gitea_path_segment(repository_name)
    );
    gitea_json(&state, &base_url, &access_token, &repository_path).await?;

    for row in state
        .database
        .client
        .query(
            "SELECT project_id, config FROM integration WHERE type = 'gitea' AND COALESCE(is_active, TRUE) = TRUE",
            &[],
        )
        .await
        .map_err(database_error)?
    {
        if row_string(&row, "project_id")? == project_id {
            continue;
        }
        let config = integration_config(&row)?;
        let other_base = config
            .get("baseUrl")
            .and_then(Value::as_str)
            .map(|value| value.trim_end_matches('/'))
            .unwrap_or_default();
        if other_base == base_url
            && config.get("repositoryOwner").and_then(Value::as_str) == Some(owner)
            && config.get("repositoryName").and_then(Value::as_str) == Some(repository_name)
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("Repository {owner}/{repository_name} on this Gitea instance is already linked to another project"),
            ));
        }
    }

    let webhook_secret = previous_config
        .as_ref()
        .and_then(|config| config.get("webhookSecret"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()));
    let config = json!({
        "baseUrl": base_url,
        "accessToken": access_token,
        "repositoryOwner": owner,
        "repositoryName": repository_name,
        "webhookSecret": webhook_secret,
        "branchPattern": "{slug}-{number}",
        "commentTaskLinkOnGiteaIssue": true,
        "statusTransitions": {
            "onBranchPush": "in-progress",
            "onPROpen": "in-review",
            "onPRMerge": "done"
        }
    });
    let serialized = serde_json::to_string(&config).map_err(database_error)?;
    if let Some(existing) = existing {
        let id = row_string(&existing, "id")?;
        state
            .database
            .client
            .execute(
                "UPDATE integration SET config = $2, is_active = TRUE, updated_at = NOW() WHERE id = $1",
                &[&id, &serialized],
            )
            .await
            .map_err(database_error)?;
    } else {
        let id = Uuid::new_v4().simple().to_string();
        state
            .database
            .client
            .execute(
                "INSERT INTO integration (id, project_id, type, config, is_active) VALUES ($1, $2, 'gitea', $3, TRUE)",
                &[&id, &project_id, &serialized],
            )
            .await
            .map_err(database_error)?;
    }
    let row = integration_row(&state, &project_id, "gitea")
        .await?
        .ok_or_else(|| database_error("Gitea integration was not saved"))?;
    Ok(Json(gitea_integration_response(
        &row,
        true,
        &state.api_base_url,
    )?))
}

async fn update_gitea_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<UpdateGiteaIntegrationInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let Some(existing) = integration_row(&state, &project_id, "gitea").await? else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Integration not found",
        ));
    };
    let mut config = integration_config(&existing)?;
    if let Some(comment_link) = input.comment_task_link_on_gitea_issue {
        config["commentTaskLinkOnGiteaIssue"] = Value::Bool(comment_link);
    }
    let serialized = serde_json::to_string(&config).map_err(database_error)?;
    let id = row_string(&existing, "id")?;
    let is_active = input.is_active.unwrap_or(
        existing
            .try_get::<_, bool>("is_active")
            .map_err(database_error)?,
    );
    state
        .database
        .client
        .execute(
            "UPDATE integration SET config = $2, is_active = $3, updated_at = NOW() WHERE id = $1",
            &[&id, &serialized, &is_active],
        )
        .await
        .map_err(database_error)?;
    let row = integration_row(&state, &project_id, "gitea")
        .await?
        .ok_or_else(|| database_error("Gitea integration was not saved"))?;
    Ok(Json(gitea_integration_response(
        &row,
        true,
        &state.api_base_url,
    )?))
}

async fn delete_gitea_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "workspace", "manage_settings")
        .await?;
    let Some(row) = integration_row(&state, &project_id, "gitea").await? else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Gitea integration not found",
        ));
    };
    let id = row_string(&row, "id")?;
    state
        .database
        .client
        .execute("DELETE FROM integration WHERE id = $1", &[&id])
        .await
        .map_err(database_error)?;
    Ok(Json(json!({
        "success": true,
        "message": "Gitea integration deleted"
    })))
}

fn imported_issue_status_priority(labels: &Value) -> (String, Option<String>) {
    let mut status = None;
    let mut priority = None;
    if let Some(labels) = labels.as_array() {
        for label in labels {
            let name = label
                .as_str()
                .or_else(|| label.get("name").and_then(Value::as_str))
                .unwrap_or_default()
                .trim();
            if let Some(value) = name.strip_prefix("status:") {
                let value = value.trim().to_lowercase();
                if !value.is_empty()
                    && value.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '-'
                    })
                {
                    status = Some(value);
                }
            }
            if let Some(value) = name.strip_prefix("priority:") {
                if matches!(value, "low" | "medium" | "high" | "urgent") {
                    priority = Some(value.to_string());
                }
            }
        }
    }
    (status.unwrap_or_else(|| "to-do".to_string()), priority)
}

async fn imported_external_link(
    state: &AppState,
    integration_id: &str,
    resource_type: &str,
    external_id: &str,
) -> Result<Option<(String, String)>, ApiError> {
    state
        .database
        .client
        .query_opt(
            "SELECT id, task_id FROM external_link WHERE integration_id = $1 AND resource_type = $2 AND external_id = $3 LIMIT 1",
            &[&integration_id, &resource_type, &external_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| {
            Ok((
                row_string(&row, "id")?,
                row_string(&row, "task_id")?,
            ))
        })
        .transpose()
}

async fn import_external_labels(
    state: &AppState,
    labels: &Value,
    task_id: &str,
    workspace_id: &str,
) -> Result<(), ApiError> {
    let Some(labels) = labels.as_array() else {
        return Ok(());
    };
    for label in labels {
        let name = label
            .as_str()
            .or_else(|| label.get("name").and_then(Value::as_str))
            .unwrap_or_default()
            .trim();
        if name.is_empty() || name.starts_with("priority:") || name.starts_with("status:") {
            continue;
        }
        let color = label
            .get("color")
            .and_then(Value::as_str)
            .map(|value| format!("#{}", value.trim_start_matches('#')))
            .filter(|value| value.len() > 1)
            .unwrap_or_else(|| "#6B7280".to_string());
        let color = state
            .database
            .client
            .query_opt(
                "SELECT color FROM label WHERE workspace_id = $1 AND task_id IS NULL AND name = $2 LIMIT 1",
                &[&workspace_id, &name],
            )
            .await
            .map_err(database_error)?
            .and_then(|row| row_optional_string(&row, "color").ok().flatten())
            .unwrap_or(color);
        state
            .database
            .client
            .execute(
                "INSERT INTO label (id, name, color, task_id, workspace_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) ON CONFLICT (task_id, name) DO NOTHING",
                &[&Uuid::new_v4().to_string(), &name, &color, &task_id, &workspace_id],
            )
            .await
            .map_err(database_error)?;
    }
    Ok(())
}

async fn import_gitea_comments(
    state: &AppState,
    base_url: &str,
    access_token: &str,
    owner: &str,
    repository: &str,
    issue_number: i64,
    task_id: &str,
) -> Result<(), ApiError> {
    for page in 1..=50 {
        let path = format!(
            "/repos/{}/{}/issues/{issue_number}/comments?page={page}&limit=100",
            gitea_path_segment(owner),
            gitea_path_segment(repository),
        );
        let comments = gitea_json(state, base_url, access_token, &path).await?;
        let Some(comments) = comments.as_array() else {
            return Ok(());
        };
        if comments.is_empty() {
            break;
        }
        for comment in comments {
            let username = comment
                .get("user")
                .and_then(|value| value.get("login").or_else(|| value.get("username")))
                .and_then(Value::as_str)
                .unwrap_or("Unknown");
            if username.ends_with("[bot]") {
                continue;
            }
            let url = comment
                .get("html_url")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if url.is_empty() {
                continue;
            }
            let body = comment
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let avatar = comment
                .get("user")
                .and_then(|value| value.get("avatar_url"))
                .and_then(Value::as_str);
            state
                .database
                .client
                .execute(
                    "INSERT INTO activity (id, task_id, type, content, external_user_name, external_user_avatar, external_source, external_url, created_at, updated_at) VALUES ($1, $2, 'comment', $3, $4, $5, 'gitea', $6, NOW(), NOW()) ON CONFLICT (task_id, external_source, external_url) DO NOTHING",
                    &[&Uuid::new_v4().to_string(), &task_id, &body, &username, &avatar, &url],
                )
                .await
                .map_err(database_error)?;
        }
        if comments.len() < 100 {
            break;
        }
    }
    Ok(())
}

async fn import_gitea_issue(
    state: &AppState,
    auth: &AuthContext,
    headers: &HeaderMap,
    integration_id: &str,
    project_id: &str,
    workspace_id: &str,
    config: &Value,
    issue: &Value,
) -> Result<&'static str, ApiError> {
    let number = issue
        .get("number")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_GATEWAY, "Gitea issue has no number"))?;
    let number_string = number.to_string();
    let title = issue
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Untitled issue")
        .to_string();
    let description = issue
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let (status, priority) =
        imported_issue_status_priority(issue.get("labels").unwrap_or(&Value::Null));
    let existing = imported_external_link(state, integration_id, "issue", &number_string).await?;
    let was_existing = existing.is_some();
    let task_id = if let Some((link_id, task_id)) = existing {
        state
            .database
            .client
            .execute(
                "UPDATE task SET title = $1, description = $2, status = $3, priority = COALESCE($4, priority), updated_at = NOW() WHERE id = $5",
                &[&title, &description, &status, &priority, &task_id],
            )
            .await
            .map_err(database_error)?;
        let url = issue
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let metadata = json!({
            "state": issue.get("state").and_then(Value::as_str),
            "createdFrom": "gitea-import",
        });
        let metadata = serde_json::to_string(&metadata).map_err(database_error)?;
        state
            .database
            .client
            .execute(
                "UPDATE external_link SET url = $1, title = $2, metadata = $3, updated_at = NOW() WHERE id = $4",
                &[&url, &title, &metadata, &link_id],
            )
            .await
            .map_err(database_error)?;
        task_id
    } else {
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
        let column_id = column_for_status(&state.database, project_id, &status).await?;
        let position: i32 = state
            .database
            .client
            .query_one(
                "SELECT COALESCE(MAX(position), 0) + 1 AS position FROM task WHERE project_id = $1 AND status = $2",
                &[&project_id, &status],
            )
            .await
            .map_err(database_error)?
            .try_get("position")
            .map_err(database_error)?;
        let task_id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                "INSERT INTO task (id, project_id, position, number, title, description, status, column_id, priority, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())",
                &[&task_id, &project_id, &position, &number, &title, &description, &status, &column_id, &priority],
            )
            .await
            .map_err(database_error)?;
        let url = issue
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let metadata = json!({
            "state": issue.get("state").and_then(Value::as_str),
            "createdFrom": "gitea-import",
            "author": issue
                .get("user")
                .and_then(|value| value.get("login").or_else(|| value.get("username")))
                .and_then(Value::as_str),
        });
        let metadata = serde_json::to_string(&metadata).map_err(database_error)?;
        state
            .database
            .client
            .execute(
                "INSERT INTO external_link (id, task_id, integration_id, resource_type, external_id, url, title, metadata, created_at, updated_at) VALUES ($1, $2, $3, 'issue', $4, $5, $6, $7, NOW(), NOW())",
                &[&Uuid::new_v4().to_string(), &task_id, &integration_id, &number_string, &url, &title, &metadata],
            )
            .await
            .map_err(database_error)?;
        let task = task_by_id(&state.database, &task_id).await?;
        publish_task_event(
            state,
            "TASK_CREATED",
            task.project_id,
            task.id,
            auth,
            headers,
        );
        task_id
    };
    import_external_labels(
        state,
        issue.get("labels").unwrap_or(&Value::Null),
        &task_id,
        workspace_id,
    )
    .await?;
    let base_url = config
        .get("baseUrl")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let access_token = config
        .get("accessToken")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let owner = config
        .get("repositoryOwner")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let repository = config
        .get("repositoryName")
        .and_then(Value::as_str)
        .unwrap_or_default();
    import_gitea_comments(
        state,
        base_url,
        access_token,
        owner,
        repository,
        number,
        &task_id,
    )
    .await?;
    Ok(if was_existing { "updated" } else { "imported" })
}

async fn import_gitea_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ImportIntegrationInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_project(&state, &headers, &input.project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "task", "create").await?;
    let integration = integration_row(&state, &input.project_id, "gitea")
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Gitea integration not found"))?;
    if !integration
        .try_get::<_, bool>("is_active")
        .map_err(database_error)?
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Gitea integration is not active",
        ));
    }
    let integration_id = row_string(&integration, "id")?;
    let config = integration_config(&integration)?;
    let base_url = normalize_gitea_base_url(
        config
            .get("baseUrl")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let access_token = config
        .get("accessToken")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Gitea access token is missing"))?;
    let owner = config
        .get("repositoryOwner")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(StatusCode::BAD_REQUEST, "Gitea repository owner is missing")
        })?;
    let repository = config
        .get("repositoryName")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(StatusCode::BAD_REQUEST, "Gitea repository name is missing")
        })?;

    let mut imported = 0;
    let mut updated = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();
    for page in 1..=50 {
        let path = format!(
            "/repos/{}/{}/issues?state=open&page={page}&limit=100",
            gitea_path_segment(owner),
            gitea_path_segment(repository),
        );
        let issues = gitea_json(&state, &base_url, access_token, &path).await?;
        let Some(issues) = issues.as_array() else {
            break;
        };
        if issues.is_empty() {
            break;
        }
        for issue in issues {
            if issue.get("pull_request").is_some() {
                skipped += 1;
                continue;
            }
            match import_gitea_issue(
                &state,
                &auth,
                &headers,
                &integration_id,
                &input.project_id,
                &workspace_id,
                &config,
                issue,
            )
            .await
            {
                Ok("imported") => imported += 1,
                Ok("updated") => updated += 1,
                Ok(_) => skipped += 1,
                Err(error) => errors.push(format!(
                    "Issue #{}: {}",
                    issue
                        .get("number")
                        .and_then(Value::as_i64)
                        .unwrap_or_default(),
                    error.message
                )),
            }
        }
        if issues.len() < 100 {
            break;
        }
    }
    Ok(Json(json!({
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": if errors.is_empty() { Value::Null } else { json!(errors) },
    })))
}

fn verify_hmac_hex(secret: &str, payload: &[u8], provided: &str) -> bool {
    let provided = provided
        .trim()
        .strip_prefix("sha256=")
        .or_else(|| provided.trim().strip_prefix("SHA256="))
        .unwrap_or(provided.trim());
    let expected = hex_digest(&hmac_sha256(
        secret.as_bytes(),
        &String::from_utf8_lossy(payload),
    ));
    if provided.len() != expected.len() {
        return false;
    }
    provided
        .as_bytes()
        .iter()
        .zip(expected.as_bytes())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

async fn gitea_webhook(
    State(state): State<AppState>,
    Path(integration_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let integration = integration_row_by_id(&state, &integration_id, "gitea").await?;
    let config = integration_config(&integration)?;
    let secret = config
        .get("webhookSecret")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Webhook secret not configured"))?;
    let signature = headers
        .get("x-gitea-signature")
        .or_else(|| headers.get("X-Gitea-Signature"))
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Missing signature"))?;
    if !verify_hmac_hex(secret, &body, signature) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid webhook signature",
        ));
    }
    let event = headers
        .get("x-gitea-event")
        .or_else(|| headers.get("X-Gitea-Event"))
        .or_else(|| headers.get("x-github-event"))
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Missing event name"))?;
    let payload: Value = serde_json::from_slice(&body).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid JSON payload: {error}"),
        )
    })?;
    let action = payload
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if matches!(event, "issues" | "issue") {
        let issue = payload.get("issue").unwrap_or(&payload);
        let issue_number = issue
            .get("number")
            .and_then(Value::as_i64)
            .or_else(|| issue.get("index").and_then(Value::as_i64));
        if let Some(issue_number) = issue_number {
            if let Some((_, task_id)) =
                imported_external_link(&state, &integration_id, "issue", &issue_number.to_string())
                    .await?
            {
                let title = issue.get("title").and_then(Value::as_str);
                let description = issue.get("body").and_then(Value::as_str);
                let status = match action {
                    "closed" => Some("done"),
                    "reopened" | "opened" | "created" => Some("to-do"),
                    _ => None,
                };
                state
                    .database
                    .client
                    .execute(
                        "UPDATE task SET title = COALESCE($1, title), description = COALESCE($2, description), status = COALESCE($3, status), updated_at = NOW() WHERE id = $4",
                        &[&title, &description, &status, &task_id],
                    )
                    .await
                    .map_err(database_error)?;
            }
        }
    } else if matches!(event, "issue_comment" | "issue_comment_created") && action == "created" {
        let issue = payload.get("issue").unwrap_or(&Value::Null);
        let comment = payload.get("comment").unwrap_or(&Value::Null);
        if let Some(issue_number) = issue
            .get("number")
            .and_then(Value::as_i64)
            .or_else(|| issue.get("index").and_then(Value::as_i64))
        {
            if let Some((_, task_id)) =
                imported_external_link(&state, &integration_id, "issue", &issue_number.to_string())
                    .await?
            {
                let url = comment
                    .get("html_url")
                    .or_else(|| comment.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let username = comment
                    .get("user")
                    .and_then(|value| value.get("login").or_else(|| value.get("username")))
                    .and_then(Value::as_str)
                    .unwrap_or("gitea-webhook");
                let content = comment
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !url.is_empty() {
                    state
                        .database
                        .client
                        .execute(
                            "INSERT INTO activity (id, task_id, type, content, external_user_name, external_source, external_url, created_at, updated_at) VALUES ($1, $2, 'comment', $3, $4, 'gitea', $5, NOW(), NOW()) ON CONFLICT (task_id, external_source, external_url) DO NOTHING",
                            &[&Uuid::new_v4().to_string(), &task_id, &content, &username, &url],
                        )
                        .await
                        .map_err(database_error)?;
                }
            }
        }
    }
    Ok(Json(json!({ "status": "success" })))
}

fn mcp_object_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn mcp_string_schema() -> Value {
    json!({ "type": "string", "minLength": 1 })
}

fn mcp_optional_string_schema() -> Value {
    json!({ "type": "string" })
}

fn mcp_tool_definitions() -> Value {
    let string = mcp_string_schema();
    let optional_string = mcp_optional_string_schema();
    let priority = json!({
        "type": "string",
        "enum": ["no-priority", "low", "medium", "high", "urgent"],
    });
    let date_time = json!({ "type": "string", "format": "date-time" });
    Value::Array(vec![
        json!({
            "name": "whoami",
            "description": "Return the current Kaneo session and user.",
            "inputSchema": mcp_object_schema(json!({}), &[]),
        }),
        json!({
            "name": "list_workspaces",
            "description": "List workspaces the signed-in user can access.",
            "inputSchema": mcp_object_schema(json!({}), &[]),
        }),
        json!({
            "name": "list_projects",
            "description": "List projects in a workspace.",
            "inputSchema": mcp_object_schema(json!({
                "workspaceId": string,
                "includeArchived": {"type": "boolean"},
            }), &["workspaceId"]),
        }),
        json!({
            "name": "get_project",
            "description": "Get a single project by ID.",
            "inputSchema": mcp_object_schema(json!({"id": string}), &["id"]),
        }),
        json!({
            "name": "create_project",
            "description": "Create a project in a workspace.",
            "inputSchema": mcp_object_schema(json!({
                "name": string,
                "workspaceId": string,
                "icon": string,
                "slug": string,
                "description": optional_string,
                "localPath": optional_string,
            }), &["name", "workspaceId", "icon", "slug"]),
        }),
        json!({
            "name": "update_project",
            "description": "Update project metadata; omitted fields are preserved.",
            "inputSchema": mcp_object_schema(json!({
                "id": string,
                "name": optional_string,
                "icon": {"type": "string"},
                "slug": optional_string,
                "description": {"type": "string"},
                "isPublic": {"type": "boolean"},
                "localPath": optional_string,
            }), &["id"]),
        }),
        json!({
            "name": "list_tasks",
            "description": "List tasks for a project with optional filters and sorting.",
            "inputSchema": mcp_object_schema(json!({
                "projectId": string,
                "status": optional_string,
                "priority": priority,
                "assigneeId": optional_string,
                "page": {"type": "integer", "minimum": 1},
                "limit": {"type": "integer", "minimum": 1},
                "sortBy": {"type": "string"},
                "sortOrder": {"type": "string", "enum": ["asc", "desc"]},
                "dueBefore": date_time,
                "dueAfter": date_time,
            }), &["projectId"]),
        }),
        json!({
            "name": "get_task",
            "description": "Get a task by ID.",
            "inputSchema": mcp_object_schema(json!({"taskId": string}), &["taskId"]),
        }),
        json!({
            "name": "create_task",
            "description": "Create a task in a project.",
            "inputSchema": mcp_object_schema(json!({
                "projectId": string,
                "title": string,
                "description": {"type": "string"},
                "priority": priority,
                "status": string,
                "startDate": date_time,
                "dueDate": date_time,
                "userId": optional_string,
            }), &["projectId", "title", "description", "priority", "status"]),
        }),
        json!({
            "name": "update_task",
            "description": "Update a task; omitted fields are preserved.",
            "inputSchema": mcp_object_schema(json!({
                "taskId": string,
                "title": optional_string,
                "description": {"type": ["string", "null"]},
                "status": optional_string,
                "priority": priority,
                "projectId": optional_string,
                "position": {"type": "number"},
                "startDate": {"type": ["string", "null"], "format": "date-time"},
                "dueDate": {"type": ["string", "null"], "format": "date-time"},
                "userId": {"type": ["string", "null"]},
            }), &["taskId"]),
        }),
        json!({
            "name": "move_task",
            "description": "Move a task to another project and optional status.",
            "inputSchema": mcp_object_schema(json!({
                "taskId": string,
                "destinationProjectId": string,
                "destinationStatus": optional_string,
            }), &["taskId", "destinationProjectId"]),
        }),
        json!({
            "name": "update_task_status",
            "description": "Update only the status of a task.",
            "inputSchema": mcp_object_schema(json!({"taskId": string, "status": string}), &["taskId", "status"]),
        }),
        json!({
            "name": "list_task_comments",
            "description": "List comments on a task.",
            "inputSchema": mcp_object_schema(json!({"taskId": string}), &["taskId"]),
        }),
        json!({
            "name": "create_task_comment",
            "description": "Add a comment to a task.",
            "inputSchema": mcp_object_schema(json!({"taskId": string, "content": string}), &["taskId", "content"]),
        }),
        json!({
            "name": "update_task_comment",
            "description": "Update one of your comments on a task.",
            "inputSchema": mcp_object_schema(json!({"commentId": string, "content": string}), &["commentId", "content"]),
        }),
        json!({
            "name": "delete_task_comment",
            "description": "Delete one of your comments from a task.",
            "inputSchema": mcp_object_schema(json!({"commentId": string}), &["commentId"]),
        }),
        json!({
            "name": "list_workspace_labels",
            "description": "List labels defined in a workspace.",
            "inputSchema": mcp_object_schema(json!({"workspaceId": string}), &["workspaceId"]),
        }),
        json!({
            "name": "create_label",
            "description": "Create a label in a workspace, optionally attached to a task.",
            "inputSchema": mcp_object_schema(json!({
                "name": string,
                "color": {"type": "string", "pattern": "^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$"},
                "workspaceId": string,
                "taskId": optional_string,
            }), &["name", "color", "workspaceId"]),
        }),
        json!({
            "name": "attach_label_to_task",
            "description": "Attach an existing label to a task.",
            "inputSchema": mcp_object_schema(json!({"labelId": string, "taskId": string}), &["labelId", "taskId"]),
        }),
        json!({
            "name": "detach_label_from_task",
            "description": "Detach a label from its current task.",
            "inputSchema": mcp_object_schema(json!({"labelId": string}), &["labelId"]),
        }),
        json!({
            "name": "create_task_relation",
            "description": "Create a subtask, blocks, or related relation between tasks.",
            "inputSchema": mcp_object_schema(json!({
                "sourceTaskId": string,
                "targetTaskId": string,
                "relationType": {"type": "string", "enum": ["subtask", "blocks", "related"]},
            }), &["sourceTaskId", "targetTaskId", "relationType"]),
        }),
        json!({
            "name": "get_task_relations",
            "description": "List all relations involving a task.",
            "inputSchema": mcp_object_schema(json!({"taskId": string}), &["taskId"]),
        }),
        json!({
            "name": "delete_task_relation",
            "description": "Delete a task relation by relation ID.",
            "inputSchema": mcp_object_schema(json!({"id": string}), &["id"]),
        }),
        json!({
            "name": "delete_label",
            "description": "Delete a task-associated label by ID.",
            "inputSchema": mcp_object_schema(json!({"id": string}), &["id"]),
        }),
        json!({
            "name": "orchestrator_status",
            "description": "Read the current orchestrator conversation, child runs, and status.",
            "inputSchema": mcp_object_schema(json!({
                "orchestratorId": string,
            }), &["orchestratorId"]),
        }),
        json!({
            "name": "orchestrator_children",
            "description": "List the child agent runs managed by an orchestrator.",
            "inputSchema": mcp_object_schema(json!({
                "orchestratorId": string,
            }), &["orchestratorId"]),
        }),
        json!({
            "name": "orchestrator_delegate",
            "description": "Delegate one independent Kanban task to a child agent.",
            "inputSchema": mcp_object_schema(json!({
                "orchestratorId": string,
                "taskId": optional_string,
                "prompt": string,
                "cwd": optional_string,
                "model": optional_string,
                "networkAccess": {"type": "boolean"},
                "maxSeconds": {"type": "integer", "minimum": 60},
            }), &["orchestratorId", "prompt"]),
        }),
    ])
}

fn mcp_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn mcp_query(pairs: &[(&str, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn mcp_required_string(args: &Value, key: &str) -> Result<String, String> {
    match args.get(key) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.clone()),
        Some(Value::String(_)) => Err(format!("{key} must not be empty")),
        Some(_) => Err(format!("{key} must be a string")),
        None => Err(format!("Missing required argument: {key}")),
    }
}

fn mcp_required_text(args: &Value, key: &str) -> Result<String, String> {
    match args.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(format!("{key} must be a string")),
        None => Err(format!("Missing required argument: {key}")),
    }
}

fn mcp_optional_string(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(format!("{key} must not be empty")),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

fn mcp_optional_text(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

fn mcp_nullable_string(args: &Value, key: &str) -> Result<Option<Option<String>>, String> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(Some(value.clone()))),
        Some(Value::String(_)) => Err(format!("{key} must not be empty")),
        Some(_) => Err(format!("{key} must be a string or null")),
    }
}

fn mcp_optional_bool(args: &Value, key: &str) -> Result<Option<bool>, String> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

fn mcp_optional_positive_i64(args: &Value, key: &str) -> Result<Option<i64>, String> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::Number(value)) => {
            let Some(value) = value.as_i64() else {
                return Err(format!("{key} must be a positive integer"));
            };
            if value < 1 {
                return Err(format!("{key} must be a positive integer"));
            }
            Ok(Some(value))
        }
        Some(_) => Err(format!("{key} must be a positive integer")),
    }
}

fn mcp_priority(args: &Value, key: &str, required: bool) -> Result<Option<String>, String> {
    let value = if required {
        Some(mcp_required_string(args, key)?)
    } else {
        mcp_optional_string(args, key)?
    };
    if let Some(value) = value {
        if !matches!(
            value.as_str(),
            "no-priority" | "low" | "medium" | "high" | "urgent"
        ) {
            return Err(format!("{key} is not a valid task priority"));
        }
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

fn mcp_existing_optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn mcp_i32_value(value: &Value, key: &str) -> Result<i32, String> {
    let value = value
        .as_i64()
        .ok_or_else(|| format!("{key} must be a number"))?;
    i32::try_from(value).map_err(|_| format!("{key} is outside the supported range"))
}

async fn mcp_api_request(
    state: &AppState,
    auth: &AuthContext,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let url = format!("{}{}", state.api_base_url.trim_end_matches('/'), path);
    let mut request = state
        .http
        .request(method, url)
        .timeout(std::time::Duration::from_secs(10))
        .header("authorization", format!("Bearer {}", auth.credential));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("{path}: {error}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("{path}: could not read response: {error}"))?;
    let value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str::<Value>(&text).unwrap_or_else(|_| Value::String(text.clone()))
    };
    if !status.is_success() {
        let detail = value
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| value.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        return Err(format!("{path}: {detail}"));
    }
    Ok(value)
}

async fn mcp_call_tool(
    state: &AppState,
    auth: &AuthContext,
    name: &str,
    args: &Value,
) -> Result<Value, String> {
    match name {
        "whoami" => {
            mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                "/api/auth/get-session",
                None,
            )
            .await
        }
        "list_workspaces" => {
            mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                "/api/auth/organization/list",
                None,
            )
            .await
        }
        "list_projects" => {
            let workspace_id = mcp_required_string(args, "workspaceId")?;
            let include_archived = mcp_optional_bool(args, "includeArchived")? == Some(true);
            let query = if include_archived {
                mcp_query(&[
                    ("workspaceId", workspace_id),
                    ("includeArchived", "true".to_string()),
                ])
            } else {
                mcp_query(&[("workspaceId", workspace_id)])
            };
            mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/project?{query}"),
                None,
            )
            .await
        }
        "get_project" => {
            let id = mcp_required_string(args, "id")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/project/{}", mcp_path_segment(&id)),
                None,
            )
            .await
        }
        "create_project" => {
            let body = json!({
                "name": mcp_required_string(args, "name")?,
                "workspaceId": mcp_required_string(args, "workspaceId")?,
                "icon": mcp_required_string(args, "icon")?,
                "slug": mcp_required_string(args, "slug")?,
                "description": mcp_optional_text(args, "description")?,
                "localPath": mcp_optional_text(args, "localPath")?,
            });
            mcp_api_request(
                state,
                auth,
                reqwest::Method::POST,
                "/api/project",
                Some(body),
            )
            .await
        }
        "update_project" => {
            let id = mcp_required_string(args, "id")?;
            let existing = mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/project/{}", mcp_path_segment(&id)),
                None,
            )
            .await?;
            let name = mcp_optional_string(args, "name")?.unwrap_or_else(|| {
                existing
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            });
            if name.trim().is_empty() {
                return Err("Cannot update project: missing name.".to_string());
            }
            let icon = mcp_optional_text(args, "icon")?.unwrap_or_else(|| {
                existing
                    .get("icon")
                    .and_then(Value::as_str)
                    .unwrap_or("Layout")
                    .to_string()
            });
            let slug = mcp_optional_string(args, "slug")?.unwrap_or_else(|| {
                existing
                    .get("slug")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            });
            if slug.trim().is_empty() {
                return Err("Cannot update project: missing slug.".to_string());
            }
            let description = mcp_optional_text(args, "description")?.unwrap_or_else(|| {
                existing
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            });
            let is_public = mcp_optional_bool(args, "isPublic")?.unwrap_or_else(|| {
                existing
                    .get("isPublic")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            });
            let local_path = mcp_optional_text(args, "localPath")?;
            let mut body = json!({
                "name": name,
                "icon": icon,
                "slug": slug,
                "description": description,
                "isPublic": is_public,
            });
            if let Some(local_path) = local_path {
                body["localPath"] = Value::String(local_path);
            }
            mcp_api_request(
                state,
                auth,
                reqwest::Method::PUT,
                &format!("/api/project/{}", mcp_path_segment(&id)),
                Some(body),
            )
            .await
        }
        "list_tasks" => {
            let project_id = mcp_required_string(args, "projectId")?;
            let mut pairs = vec![];
            for key in ["status", "assigneeId", "sortBy", "dueBefore", "dueAfter"] {
                if let Some(value) = mcp_optional_text(args, key)? {
                    if value.trim().is_empty() {
                        return Err(format!("{key} must not be empty"));
                    }
                    pairs.push((key, value));
                }
            }
            if let Some(priority) = mcp_priority(args, "priority", false)? {
                pairs.push(("priority", priority));
            }
            if let Some(page) = mcp_optional_positive_i64(args, "page")? {
                pairs.push(("page", page.to_string()));
            }
            if let Some(limit) = mcp_optional_positive_i64(args, "limit")? {
                pairs.push(("limit", limit.to_string()));
            }
            if let Some(sort_order) = mcp_optional_string(args, "sortOrder")? {
                if !matches!(sort_order.as_str(), "asc" | "desc") {
                    return Err("sortOrder must be asc or desc".to_string());
                }
                pairs.push(("sortOrder", sort_order));
            }
            let query = mcp_query(&pairs);
            let path = if query.is_empty() {
                format!("/api/task/tasks/{}", mcp_path_segment(&project_id))
            } else {
                format!("/api/task/tasks/{}?{query}", mcp_path_segment(&project_id))
            };
            mcp_api_request(state, auth, reqwest::Method::GET, &path, None).await
        }
        "get_task" => {
            let task_id = mcp_required_string(args, "taskId")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/task/{}", mcp_path_segment(&task_id)),
                None,
            )
            .await
        }
        "create_task" => {
            let mut body = json!({
                "title": mcp_required_string(args, "title")?,
                "description": mcp_required_text(args, "description")?,
                "priority": mcp_priority(args, "priority", true)?.unwrap_or_default(),
                "status": mcp_required_string(args, "status")?,
            });
            for key in ["startDate", "dueDate", "userId"] {
                if let Some(value) = mcp_optional_string(args, key)? {
                    body[key] = json!(value);
                }
            }
            let project_id = mcp_required_string(args, "projectId")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::POST,
                &format!("/api/task/{}", mcp_path_segment(&project_id)),
                Some(body),
            )
            .await
        }
        "update_task" => {
            let task_id = mcp_required_string(args, "taskId")?;
            let existing = mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/task/{}", mcp_path_segment(&task_id)),
                None,
            )
            .await?;
            let position = match args.get("position") {
                Some(value) => mcp_i32_value(value, "position")?,
                None => mcp_i32_value(
                    existing.get("position").ok_or_else(|| {
                        "Cannot update task: missing numeric `position` on existing task."
                            .to_string()
                    })?,
                    "position",
                )?,
            };
            let title = mcp_optional_string(args, "title")?.unwrap_or_else(|| {
                existing
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            });
            if title.trim().is_empty() {
                return Err("Cannot update task: missing title.".to_string());
            }
            let description = match args.get("description") {
                None => mcp_existing_optional_string(&existing, "description").unwrap_or_default(),
                Some(Value::Null) => String::new(),
                Some(Value::String(value)) => value.clone(),
                Some(_) => return Err("description must be a string or null".to_string()),
            };
            let status = mcp_optional_string(args, "status")?.unwrap_or_else(|| {
                existing
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            });
            if status.trim().is_empty() {
                return Err("Cannot update task: missing status.".to_string());
            }
            let priority = mcp_priority(args, "priority", false)?.or_else(|| {
                existing
                    .get("priority")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
            let Some(priority) = priority else {
                return Err("Cannot update task: invalid or missing priority.".to_string());
            };
            if !matches!(
                priority.as_str(),
                "no-priority" | "low" | "medium" | "high" | "urgent"
            ) {
                return Err("Cannot update task: invalid or missing priority.".to_string());
            }
            let project_id = mcp_optional_string(args, "projectId")?.unwrap_or_else(|| {
                existing
                    .get("projectId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            });
            if project_id.trim().is_empty() {
                return Err("Cannot update task: missing projectId.".to_string());
            }
            let mut body = json!({
                "title": title,
                "description": description,
                "status": status,
                "priority": priority,
                "projectId": project_id,
                "position": position,
            });
            for key in ["startDate", "dueDate"] {
                let value = match args.get(key) {
                    None => mcp_existing_optional_string(&existing, key),
                    Some(Value::Null) => None,
                    Some(Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
                    Some(Value::String(_)) => return Err(format!("{key} must not be empty")),
                    Some(_) => return Err(format!("{key} must be a string or null")),
                };
                if let Some(value) = value {
                    body[key] = json!(value);
                }
            }
            if let Some(user_id) = mcp_nullable_string(args, "userId")? {
                body["userId"] = json!(user_id.unwrap_or_default());
            } else if let Some(user_id) = mcp_existing_optional_string(&existing, "userId") {
                body["userId"] = json!(user_id);
            }
            mcp_api_request(
                state,
                auth,
                reqwest::Method::PUT,
                &format!("/api/task/{}", mcp_path_segment(&task_id)),
                Some(body),
            )
            .await
        }
        "move_task" => {
            let task_id = mcp_required_string(args, "taskId")?;
            let destination_project_id = mcp_required_string(args, "destinationProjectId")?;
            let mut body = json!({
                "destinationProjectId": destination_project_id,
            });
            if let Some(destination_status) = mcp_optional_string(args, "destinationStatus")? {
                body["destinationStatus"] = json!(destination_status);
            }
            mcp_api_request(
                state,
                auth,
                reqwest::Method::PUT,
                &format!("/api/task/move/{}", mcp_path_segment(&task_id)),
                Some(body),
            )
            .await
        }
        "update_task_status" => {
            let task_id = mcp_required_string(args, "taskId")?;
            let body = json!({"status": mcp_required_string(args, "status")?});
            mcp_api_request(
                state,
                auth,
                reqwest::Method::PUT,
                &format!("/api/task/status/{}", mcp_path_segment(&task_id)),
                Some(body),
            )
            .await
        }
        "list_task_comments" => {
            let task_id = mcp_required_string(args, "taskId")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/comment/{}", mcp_path_segment(&task_id)),
                None,
            )
            .await
        }
        "create_task_comment" => {
            let task_id = mcp_required_string(args, "taskId")?;
            let body = json!({"content": mcp_required_string(args, "content")?});
            mcp_api_request(
                state,
                auth,
                reqwest::Method::POST,
                &format!("/api/comment/{}", mcp_path_segment(&task_id)),
                Some(body),
            )
            .await
        }
        "update_task_comment" => {
            let comment_id = mcp_required_string(args, "commentId")?;
            let body = json!({"content": mcp_required_string(args, "content")?});
            mcp_api_request(
                state,
                auth,
                reqwest::Method::PUT,
                &format!("/api/comment/{}", mcp_path_segment(&comment_id)),
                Some(body),
            )
            .await
        }
        "delete_task_comment" => {
            let comment_id = mcp_required_string(args, "commentId")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::DELETE,
                &format!("/api/comment/{}", mcp_path_segment(&comment_id)),
                None,
            )
            .await
        }
        "list_workspace_labels" => {
            let workspace_id = mcp_required_string(args, "workspaceId")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/label/workspace/{}", mcp_path_segment(&workspace_id)),
                None,
            )
            .await
        }
        "create_label" => {
            let color = mcp_required_string(args, "color")?;
            if !color.starts_with('#')
                || !(color.len() == 4 || color.len() == 7)
                || !color[1..].chars().all(|value| value.is_ascii_hexdigit())
            {
                return Err("color must be a hex color like #FF6600".to_string());
            }
            let mut body = json!({
                "name": mcp_required_string(args, "name")?,
                "color": color,
                "workspaceId": mcp_required_string(args, "workspaceId")?,
            });
            if let Some(task_id) = mcp_optional_string(args, "taskId")? {
                body["taskId"] = json!(task_id);
            }
            mcp_api_request(state, auth, reqwest::Method::POST, "/api/label", Some(body)).await
        }
        "attach_label_to_task" => {
            let label_id = mcp_required_string(args, "labelId")?;
            let body = json!({"taskId": mcp_required_string(args, "taskId")?});
            mcp_api_request(
                state,
                auth,
                reqwest::Method::PUT,
                &format!("/api/label/{}/task", mcp_path_segment(&label_id)),
                Some(body),
            )
            .await
        }
        "detach_label_from_task" => {
            let label_id = mcp_required_string(args, "labelId")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::DELETE,
                &format!("/api/label/{}/task", mcp_path_segment(&label_id)),
                None,
            )
            .await
        }
        "create_task_relation" => {
            let relation_type = mcp_required_string(args, "relationType")?;
            if !matches!(relation_type.as_str(), "subtask" | "blocks" | "related") {
                return Err("relationType must be subtask, blocks, or related".to_string());
            }
            let body = json!({
                "sourceTaskId": mcp_required_string(args, "sourceTaskId")?,
                "targetTaskId": mcp_required_string(args, "targetTaskId")?,
                "relationType": relation_type,
            });
            mcp_api_request(
                state,
                auth,
                reqwest::Method::POST,
                "/api/task-relation",
                Some(body),
            )
            .await
        }
        "get_task_relations" => {
            let task_id = mcp_required_string(args, "taskId")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/task-relation/{}", mcp_path_segment(&task_id)),
                None,
            )
            .await
        }
        "delete_task_relation" => {
            let id = mcp_required_string(args, "id")?;
            mcp_api_request(
                state,
                auth,
                reqwest::Method::DELETE,
                &format!("/api/task-relation/{}", mcp_path_segment(&id)),
                None,
            )
            .await
        }
        "delete_label" => {
            let id = mcp_required_string(args, "id")?;
            let label = mcp_api_request(
                state,
                auth,
                reqwest::Method::GET,
                &format!("/api/label/{}", mcp_path_segment(&id)),
                None,
            )
            .await?;
            if !label
                .get("taskId")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            {
                return Err("Label is not associated with a task and cannot be deleted (workspace-level labels are not deletable via this endpoint).".to_string());
            }
            mcp_api_request(
                state,
                auth,
                reqwest::Method::DELETE,
                &format!("/api/label/{}", mcp_path_segment(&id)),
                None,
            )
            .await
        }
        "orchestrator_status" | "orchestrator_children" => {
            let orchestrator_id = mcp_required_string(args, "orchestratorId")?;
            orchestrator_children_value(state, auth, &orchestrator_id).await
        }
        "orchestrator_delegate" => delegate_orchestrator_child(state, auth, args).await,
        _ => Err(format!("Unknown MCP tool: {name}")),
    }
}

fn mcp_tool_result(value: Value) -> Value {
    let text = match value {
        Value::String(value) => value,
        value => serde_json::to_string_pretty(&value).unwrap_or_else(|_| "null".to_string()),
    };
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": false,
    })
}

fn mcp_tool_error(message: impl Into<String>) -> Value {
    let value = json!({"error": message.into()});
    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{\"error\":\"unknown\"}".to_string()),
        }],
        "isError": true,
    })
}

fn mcp_session_id(headers: &HeaderMap) -> String {
    headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn mcp_response(payload: Value, status: StatusCode, session_id: &str) -> Response {
    let mut response = (status, Json(payload)).into_response();
    if let Ok(value) = HeaderValue::from_str(session_id) {
        response.headers_mut().insert("mcp-session-id", value);
    }
    response
}

fn mcp_rpc_result(id: Value, result: Value, session_id: &str) -> Response {
    mcp_response(
        json!({"jsonrpc": "2.0", "id": id, "result": result}),
        StatusCode::OK,
        session_id,
    )
}

fn mcp_rpc_error(id: Value, code: i32, message: impl Into<String>, session_id: &str) -> Response {
    mcp_response(
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message.into()},
        }),
        StatusCode::OK,
        session_id,
    )
}

fn mcp_unauthorized_response(state: &AppState) -> Response {
    let resource_metadata = format!(
        "{}/api/.well-known/oauth-protected-resource/api/mcp",
        state.api_base_url.trim_end_matches('/')
    );
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "invalid_token",
            "error_description": "Missing or invalid token",
        })),
    )
        .into_response();
    if let Ok(value) =
        HeaderValue::from_str(&format!("Bearer resource_metadata=\"{resource_metadata}\""))
    {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

async fn mcp_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Response, ApiError> {
    let auth = match authenticate(&state, &headers).await {
        Ok(auth) => auth,
        Err(error) if error.status == StatusCode::UNAUTHORIZED => {
            return Ok(mcp_unauthorized_response(&state));
        }
        Err(error) => return Err(error),
    };
    let session_id = mcp_session_id(&headers);
    let id = request.get("id").cloned();
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Ok(match id {
            Some(id) => mcp_rpc_error(id, -32600, "Invalid Request", &session_id),
            None => mcp_response(Value::Null, StatusCode::ACCEPTED, &session_id),
        });
    };
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => {
            let protocol_version = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-06-18");
            Ok(json!({
                "protocolVersion": protocol_version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "kaneo-mcp", "version": "1.0.0"},
            }))
        }
        "notifications/initialized" => {
            return Ok(mcp_response(Value::Null, StatusCode::ACCEPTED, &session_id));
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": mcp_tool_definitions()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).ok_or_else(|| {
                ApiError::new(StatusCode::BAD_REQUEST, "MCP tool name is required")
            })?;
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if !arguments.is_object() {
                Ok(mcp_tool_error("MCP tool arguments must be an object"))
            } else {
                match mcp_call_tool(&state, &auth, name, &arguments).await {
                    Ok(value) => Ok(mcp_tool_result(value)),
                    Err(error) => Ok(mcp_tool_error(error)),
                }
            }
        }
        _ => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("Unsupported MCP method: {method}"),
        )),
    };
    let response = match (id, result) {
        (Some(id), Ok(result)) => mcp_rpc_result(id, result, &session_id),
        (Some(id), Err(error)) => mcp_rpc_error(id, -32601, error.message, &session_id),
        (None, Ok(_)) | (None, Err(_)) => {
            mcp_response(Value::Null, StatusCode::ACCEPTED, &session_id)
        }
    };
    Ok(response)
}

async fn mcp_get_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    match authenticate(&state, &headers).await {
        Ok(_) => {
            let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("POST"));
            Ok(response)
        }
        Err(error) if error.status == StatusCode::UNAUTHORIZED => {
            Ok(mcp_unauthorized_response(&state))
        }
        Err(error) => Err(error),
    }
}

async fn mcp_protected_resource_metadata(State(state): State<AppState>) -> Json<Value> {
    let base = state.api_base_url.trim_end_matches('/');
    Json(json!({
        "resource": format!("{base}/api/mcp"),
        "authorization_servers": [format!("{base}/api")],
    }))
}

async fn mcp_authorization_server_metadata(State(state): State<AppState>) -> Json<Value> {
    let base = state.api_base_url.trim_end_matches('/');
    Json(json!({
        "issuer": format!("{base}/api"),
        "authorization_endpoint": format!("{base}/api/mcp/authorize"),
        "token_endpoint": format!("{base}/api/mcp/token"),
        "registration_endpoint": format!("{base}/api/mcp/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
}

#[derive(Debug, Deserialize, Default)]
struct McpAuthorizationQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct McpAuthorizationDecision {
    approved: bool,
}

fn mcp_now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

fn mcp_valid_redirect_uri(value: &str) -> bool {
    if value.len() > 2048 {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")),
        "https" => true,
        scheme => {
            let mut characters = scheme.chars();
            characters
                .next()
                .is_some_and(|value| value.is_ascii_lowercase())
                && characters
                    .all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
        }
    }
}

fn mcp_http_json(payload: Value, status: StatusCode) -> Response {
    (status, Json(payload)).into_response()
}

fn mcp_oauth_error(status: StatusCode, error: &str) -> Response {
    mcp_http_json(json!({"error": error}), status)
}

fn mcp_redirect_response(url: &str) -> Response {
    match HeaderValue::from_str(url) {
        Ok(location) => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(header::LOCATION, location);
            response
        }
        Err(_) => mcp_oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_redirect"),
    }
}

fn mcp_build_authorization_redirect(
    request: &McpAuthorizationRequest,
    parameters: &[(&str, &str)],
) -> Result<String, String> {
    let mut url =
        Url::parse(&request.redirect_uri).map_err(|_| "invalid_redirect_uri".to_string())?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in parameters {
            query.append_pair(key, value);
        }
        if let Some(state) = request.state.as_deref() {
            query.append_pair("state", state);
        }
    }
    Ok(url.to_string())
}

fn mcp_trusted_origin(client_url: &str, origin: Option<&str>) -> bool {
    let Some(origin) = origin else {
        return false;
    };
    let Ok(expected) = Url::parse(client_url) else {
        return false;
    };
    let Ok(actual) = Url::parse(origin) else {
        return false;
    };
    expected.scheme() == actual.scheme()
        && expected.host_str() == actual.host_str()
        && expected.port_or_known_default() == actual.port_or_known_default()
}

async fn mcp_register(State(state): State<AppState>, Json(input): Json<Value>) -> Response {
    let Some(redirect_values) = input.get("redirect_uris").and_then(Value::as_array) else {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    };
    if redirect_values.is_empty() {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    let mut redirect_uris = Vec::with_capacity(redirect_values.len());
    for value in redirect_values {
        let Some(value) = value.as_str() else {
            return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
        };
        if !mcp_valid_redirect_uri(value) {
            return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
        }
        redirect_uris.push(value.to_string());
    }
    if input
        .get("token_endpoint_auth_method")
        .is_some_and(|value| value != "none")
        || input
            .get("grant_types")
            .is_some_and(|value| value != &json!(["authorization_code"]))
        || input
            .get("response_types")
            .is_some_and(|value| value != &json!(["code"]))
    {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    let client_name = match input.get("client_name") {
        None => None,
        Some(Value::String(value)) if value.len() <= 100 => Some(value.clone()),
        Some(_) => return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata"),
    };
    let client_id = Uuid::new_v4().to_string();
    let client = McpRegisteredClient {
        redirect_uris: redirect_uris.clone(),
        client_name: client_name.clone(),
        issued_at: mcp_now_millis() / 1000,
    };
    let issued_at = client.issued_at;
    state
        .mcp
        .lock()
        .await
        .clients
        .insert(client_id.clone(), client);
    let mut response = json!({
        "client_id": client_id,
        "client_id_issued_at": issued_at,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    });
    if let Some(client_name) = client_name {
        response["client_name"] = json!(client_name);
    }
    mcp_http_json(response, StatusCode::OK)
}

async fn mcp_authorize(
    State(state): State<AppState>,
    Query(query): Query<McpAuthorizationQuery>,
) -> Response {
    if query.response_type.as_deref() != Some("code")
        || query.code_challenge_method.as_deref() != Some("S256")
    {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(client_id) = query.client_id.filter(|value| !value.trim().is_empty()) else {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(redirect_uri) = query.redirect_uri.filter(|value| !value.trim().is_empty()) else {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(code_challenge) = query
        .code_challenge
        .filter(|value| !value.trim().is_empty())
    else {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if !mcp_valid_redirect_uri(&redirect_uri) {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }
    {
        let store = state.mcp.lock().await;
        let Some(client) = store.clients.get(&client_id) else {
            return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client");
        };
        if !client
            .redirect_uris
            .iter()
            .any(|value| value == &redirect_uri)
        {
            return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
        }
    }
    let request_id = Uuid::new_v4().to_string();
    let request = McpAuthorizationRequest {
        client_id,
        code_challenge,
        redirect_uri,
        state: query.state,
        expires_at: mcp_now_millis() + 10 * 60 * 1000,
    };
    let mut store = state.mcp.lock().await;
    store
        .authorization_requests
        .retain(|_, request| request.expires_at >= mcp_now_millis());
    if store.authorization_requests.len() >= 10_000 {
        if let Some(request_id) = store.authorization_requests.keys().next().cloned() {
            store.authorization_requests.remove(&request_id);
        }
    }
    store
        .authorization_requests
        .insert(request_id.clone(), request);
    drop(store);

    let Ok(mut consent_url) = Url::parse(&state.client_url) else {
        return mcp_oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid_client_url");
    };
    consent_url.set_path("/mcp/authorize");
    consent_url
        .query_pairs_mut()
        .append_pair("request_id", &request_id);
    mcp_redirect_response(consent_url.as_str())
}

async fn mcp_authorization_request(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> Response {
    let request = {
        let mut store = state.mcp.lock().await;
        let Some(request) = store.authorization_requests.get(&request_id).cloned() else {
            return mcp_oauth_error(StatusCode::NOT_FOUND, "invalid_or_expired_request");
        };
        if request.expires_at < mcp_now_millis() {
            store.authorization_requests.remove(&request_id);
            return mcp_oauth_error(StatusCode::NOT_FOUND, "invalid_or_expired_request");
        }
        request
    };
    let store = state.mcp.lock().await;
    let Some(client) = store.clients.get(&request.client_id) else {
        return mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client");
    };
    mcp_http_json(
        json!({
            "client_name": client.client_name.clone().unwrap_or_else(|| "MCP client".to_string()),
            "redirect_uri": request.redirect_uri,
        }),
        StatusCode::OK,
    )
}

async fn mcp_authorization_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(input): Json<McpAuthorizationDecision>,
) -> Result<Response, ApiError> {
    if !mcp_trusted_origin(
        &state.client_url,
        headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok()),
    ) {
        return Ok(mcp_oauth_error(StatusCode::FORBIDDEN, "invalid_origin"));
    }
    let auth = match authenticate(&state, &headers).await {
        Ok(auth) => auth,
        Err(error) if error.status == StatusCode::UNAUTHORIZED => {
            return Ok(mcp_oauth_error(StatusCode::UNAUTHORIZED, "unauthorized"));
        }
        Err(error) => return Err(error),
    };
    let (request, client) = {
        let mut store = state.mcp.lock().await;
        let Some(request) = store.authorization_requests.remove(&request_id) else {
            return Ok(mcp_oauth_error(
                StatusCode::NOT_FOUND,
                "invalid_or_expired_request",
            ));
        };
        if request.expires_at < mcp_now_millis() {
            return Ok(mcp_oauth_error(
                StatusCode::NOT_FOUND,
                "invalid_or_expired_request",
            ));
        }
        let Some(client) = store.clients.get(&request.client_id).cloned() else {
            return Ok(mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client"));
        };
        (request, client)
    };
    if !client
        .redirect_uris
        .iter()
        .any(|value| value == &request.redirect_uri)
    {
        return Ok(mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_client"));
    }
    if !input.approved {
        let redirect = mcp_build_authorization_redirect(&request, &[("error", "access_denied")])
            .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error))?;
        return Ok(mcp_redirect_response(&redirect));
    }
    let code = Uuid::new_v4().to_string();
    state.mcp.lock().await.codes.insert(
        code.clone(),
        McpAuthorizationCode {
            client_id: request.client_id.clone(),
            user_id: auth.user_id,
            code_challenge: request.code_challenge.clone(),
            redirect_uri: request.redirect_uri.clone(),
            expires_at: mcp_now_millis() + 5 * 60 * 1000,
        },
    );
    let redirect = mcp_build_authorization_redirect(&request, &[("code", &code)])
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error))?;
    Ok(mcp_redirect_response(&redirect))
}

fn mcp_pkce_valid(verifier: &str, challenge: &str) -> bool {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

async fn mcp_exchange_code(
    state: &AppState,
    code: &str,
    client_id: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<Option<(String, i64)>, ApiError> {
    let Some(stored) = state.mcp.lock().await.codes.remove(code) else {
        return Ok(None);
    };
    if stored.client_id != client_id
        || stored.redirect_uri != redirect_uri
        || stored.expires_at < mcp_now_millis()
        || !mcp_pkce_valid(code_verifier, &stored.code_challenge)
    {
        return Ok(None);
    }
    let access_token = Uuid::new_v4().to_string();
    let expires_in = 30 * 24 * 60 * 60_i64;
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO session (id, token, user_id, expires_at, created_at, updated_at)
              VALUES ($1, $2, $3, NOW() + INTERVAL '30 days', NOW(), NOW())
            "#,
            &[&Uuid::new_v4().to_string(), &access_token, &stored.user_id],
        )
        .await
        .map_err(database_error)?;
    Ok(Some((access_token, expires_in)))
}

async fn mcp_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, ApiError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let body = to_bytes(request.into_body(), DEFAULT_MAX_BODY_BYTES)
        .await
        .map_err(|error| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, error.to_string()))?;
    let parameters: HashMap<String, String> =
        if content_type.contains("application/x-www-form-urlencoded") {
            url::form_urlencoded::parse(&body).into_owned().collect()
        } else {
            serde_json::from_slice(&body)
                .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_request"))?
        };
    if parameters.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return Ok(mcp_oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
        ));
    }
    let Some(code) = parameters.get("code").filter(|value| !value.is_empty()) else {
        return Ok(mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_request"));
    };
    let Some(client_id) = parameters
        .get("client_id")
        .filter(|value| !value.is_empty())
    else {
        return Ok(mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_request"));
    };
    let Some(code_verifier) = parameters
        .get("code_verifier")
        .filter(|value| !value.is_empty())
    else {
        return Ok(mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_request"));
    };
    let Some(redirect_uri) = parameters
        .get("redirect_uri")
        .filter(|value| !value.is_empty())
    else {
        return Ok(mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_request"));
    };
    let Some((access_token, expires_in)) =
        mcp_exchange_code(&state, code, client_id, code_verifier, redirect_uri).await?
    else {
        return Ok(mcp_oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"));
    };
    Ok(mcp_http_json(
        json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": expires_in,
        }),
        StatusCode::OK,
    ))
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
                p.local_path,
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
                "localPath": row_optional_string(&row, "local_path")?,
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
                     p.local_path,
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
        "localPath": row_optional_string(&row, "local_path")?,
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
    let mut board = load_board(&state, &id, &query).await?;
    if !board.data.is_public {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Project is not public",
        ));
    }
    board.data.local_path = None;
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
              SELECT p.id, p.name, p.slug, p.icon, p.description, p.local_path,
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
            local_path: row_optional_string(&project_row, "local_path")?,
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
        "TASK_PRIORITY_CHANGED",
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
        "TASK_DUE_DATE_CHANGED",
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
        "TASK_ASSIGNEE_CHANGED",
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
        "TASK_DESCRIPTION_CHANGED",
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

fn auth_cookie(token: &str, clear: bool) -> String {
    if clear {
        "better-auth.session_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax".to_string()
    } else {
        format!(
            "better-auth.session_token={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax"
        )
    }
}

fn auth_response(
    value: Value,
    token: Option<&str>,
    clear_cookie: bool,
) -> Result<Response, ApiError> {
    let mut response = Json(value).into_response();
    if let Some(token) = token {
        let cookie = auth_cookie(token, false);
        let value = HeaderValue::from_str(&cookie).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not create session cookie: {error}"),
            )
        })?;
        response.headers_mut().append(header::SET_COOKIE, value);
    } else if clear_cookie {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static(
                "better-auth.session_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            ),
        );
    }
    Ok(response)
}

fn normalize_email(value: &str) -> Result<String, ApiError> {
    let email = value.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') || email.len() > 320 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid email address",
        ));
    }
    Ok(email)
}

fn validate_password(value: &str) -> Result<(), ApiError> {
    if value.chars().count() < 8 || value.chars().count() > 128 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Password must be between 8 and 128 characters",
        ));
    }
    Ok(())
}

fn slugify_workspace_name(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut last_was_dash = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash && !slug.is_empty() {
            slug.push('-');
            last_was_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "workspace".to_string()
    } else {
        slug
    }
}

fn normalize_workspace_slug(value: Option<&str>, name: &str) -> String {
    let raw = value.unwrap_or_default().trim();
    let source = if raw.is_empty() { name } else { raw };
    slugify_workspace_name(source).chars().take(80).collect()
}

async fn session_for_user(
    state: &AppState,
    user_id: &str,
    headers: &HeaderMap,
) -> Result<(String, Value), ApiError> {
    let token = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let active_organization_id = state
        .database
        .client
        .query_opt(
            "SELECT workspace_id FROM workspace_member WHERE user_id = $1 ORDER BY joined_at ASC LIMIT 1",
            &[&user_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| row_string(&row, "workspace_id"))
        .transpose()?;
    let ip_address: Option<String> = None;
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO session
                (id, expires_at, token, created_at, updated_at, ip_address,
                 user_agent, user_id, active_organization_id)
              VALUES ($1, NOW() + INTERVAL '30 days', $2, NOW(), NOW(), $3, $4, $5, $6)
            "#,
            &[
                &session_id,
                &token,
                &ip_address,
                &user_agent,
                &user_id,
                &active_organization_id,
            ],
        )
        .await
        .map_err(database_error)?;
    let role = state
        .database
        .client
        .query_opt("SELECT role FROM \"user\" WHERE id = $1", &[&user_id])
        .await
        .map_err(database_error)?
        .and_then(|row| row.try_get("role").ok());
    let auth = AuthContext {
        user_id: user_id.to_string(),
        role,
        session_token: Some(token.clone()),
        credential: token.clone(),
    };
    Ok((token, session_json(state, &auth).await?))
}

async fn sign_up_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SignUpInput>,
) -> Result<Response, ApiError> {
    let email = normalize_email(&input.email)?;
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Invalid name"));
    }
    validate_password(&input.password)?;
    let existing_user_count = state
        .database
        .client
        .query_one("SELECT COUNT(*)::bigint AS count FROM \"user\"", &[])
        .await
        .map_err(database_error)?
        .try_get::<_, i64>("count")
        .map_err(database_error)?;
    if env_true("DISABLE_REGISTRATION") && existing_user_count > 0 {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Registration is disabled",
        ));
    }
    if env_true("DISABLE_PASSWORD_REGISTRATION") && existing_user_count > 0 {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Password registration is disabled",
        ));
    }
    if state
        .database
        .client
        .query_opt(
            "SELECT id FROM \"user\" WHERE lower(email) = lower($1) LIMIT 1",
            &[&email],
        )
        .await
        .map_err(database_error)?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "User with this email already exists",
        ));
    }
    let password_hash = bcrypt_hash(&input.password, 10).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not hash password: {error}"),
        )
    })?;
    let user_id = Uuid::new_v4().to_string();
    let account_id = Uuid::new_v4().to_string();
    let role = (existing_user_count == 0).then_some("admin");
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO "user"
                (id, name, email, email_verified, locale, created_at, updated_at,
                 is_anonymous, role, banned)
              VALUES ($1, $2, $3, FALSE, $4, NOW(), NOW(), FALSE, $5, FALSE)
            "#,
            &[&user_id, &name, &email, &input.locale, &role],
        )
        .await
        .map_err(database_error)?;
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO account
                (id, account_id, provider_id, user_id, password, created_at, updated_at)
              VALUES ($1, $2, 'credential', $3, $4, NOW(), NOW())
            "#,
            &[&account_id, &email, &user_id, &password_hash],
        )
        .await
        .map_err(database_error)?;
    let (token, session) = session_for_user(&state, &user_id, &headers).await?;
    let user = session.get("user").cloned().unwrap_or(Value::Null);
    let session_record = session.get("session").cloned().unwrap_or(Value::Null);
    auth_response(
        json!({ "token": token, "user": user, "session": session_record }),
        Some(&token),
        false,
    )
}

async fn sign_in_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SignInInput>,
) -> Result<Response, ApiError> {
    let email = normalize_email(&input.email)?;
    validate_password(&input.password)?;
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT u.id, COALESCE(u.banned, FALSE) AS banned, a.password
              FROM "user" u
              INNER JOIN account a ON a.user_id = u.id AND a.provider_id = 'credential'
              WHERE lower(u.email) = lower($1)
              LIMIT 1
            "#,
            &[&email],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Invalid email or password"))?;
    let password_hash: Option<String> = row.try_get("password").map_err(database_error)?;
    let valid = password_hash
        .as_deref()
        .is_some_and(|value| bcrypt_verify(&input.password, value).unwrap_or(false));
    let banned = row.try_get::<_, bool>("banned").unwrap_or(false);
    if !valid || banned {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid email or password",
        ));
    }
    let user_id: String = row.try_get("id").map_err(database_error)?;
    let (token, session) = session_for_user(&state, &user_id, &headers).await?;
    let user = session.get("user").cloned().unwrap_or(Value::Null);
    let session_record = session.get("session").cloned().unwrap_or(Value::Null);
    auth_response(
        json!({ "token": token, "user": user, "session": session_record }),
        Some(&token),
        false,
    )
}

async fn sign_in_anonymous(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if env_true("DISABLE_GUEST_ACCESS") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Guest access is disabled",
        ));
    }

    let user_id = Uuid::new_v4().to_string();
    let suffix = &user_id[..8];
    let name = format!("Kaneo guest {suffix}");
    let email = format!("guest-{user_id}@kaneo.app");
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO "user"
                (id, name, email, email_verified, locale, created_at, updated_at,
                 is_anonymous, role, banned)
              VALUES ($1, $2, $3, FALSE, NULL, NOW(), NOW(), TRUE, NULL, FALSE)
            "#,
            &[&user_id, &name, &email],
        )
        .await
        .map_err(database_error)?;
    let (token, session) = session_for_user(&state, &user_id, &headers).await?;
    let user = session.get("user").cloned().unwrap_or(Value::Null);
    let session_record = session.get("session").cloned().unwrap_or(Value::Null);
    auth_response(
        json!({ "token": token, "user": user, "session": session_record }),
        Some(&token),
        false,
    )
}

async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    if let Some(auth) = authenticate(&state, &headers).await.ok() {
        if let Some(session_token) = auth.session_token {
            state
                .database
                .client
                .execute("DELETE FROM session WHERE token = $1", &[&session_token])
                .await
                .map_err(database_error)?;
        }
    }
    auth_response(json!({ "success": true }), None, true)
}

async fn organization_json(state: &AppState, organization_id: &str) -> Result<Value, ApiError> {
    let row = state
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
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Organization not found"))?;
    let metadata = row_optional_string(&row, "metadata")?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    Ok(json!({
        "id": row_string(&row, "id")?,
        "name": row_string(&row, "name")?,
        "slug": row_string(&row, "slug")?,
        "logo": row_optional_string(&row, "logo")?,
        "metadata": metadata,
        "description": row_optional_string(&row, "description")?,
        "createdAt": row_string(&row, "created_at")?,
    }))
}

async fn create_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OrganizationCreateInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid organization name",
        ));
    }
    let slug = normalize_workspace_slug(input.slug.as_deref(), name);
    if state
        .database
        .client
        .query_opt("SELECT id FROM workspace WHERE slug = $1 LIMIT 1", &[&slug])
        .await
        .map_err(database_error)?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Organization slug already exists",
        ));
    }
    let organization_id = Uuid::new_v4().to_string();
    let member_id = Uuid::new_v4().to_string();
    let metadata = input.metadata.as_ref().map(Value::to_string);
    let description = input
        .metadata
        .as_ref()
        .and_then(|value| value.get("description"))
        .and_then(Value::as_str)
        .map(str::to_string);
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO workspace (id, name, slug, logo, metadata, description, created_at)
              VALUES ($1, $2, $3, $4, $5, $6, NOW())
            "#,
            &[
                &organization_id,
                &name,
                &slug,
                &input.logo,
                &metadata,
                &description,
            ],
        )
        .await
        .map_err(database_error)?;
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO workspace_member (id, workspace_id, user_id, role, joined_at)
              VALUES ($1, $2, $3, 'owner', NOW())
            "#,
            &[&member_id, &organization_id, &auth.user_id],
        )
        .await
        .map_err(database_error)?;
    for role in ["viewer", "member", "admin"] {
        let permissions = serde_json::to_string(&built_in_permissions(role)).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not serialize workspace permissions: {error}"),
            )
        })?;
        let role_id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO workspace_role
                    (id, workspace_id, role, permission, created_at, updated_at)
                  VALUES ($1, $2, $3, $4, NOW(), NOW())
                "#,
                &[&role_id, &organization_id, &role, &permissions],
            )
            .await
            .map_err(database_error)?;
    }
    Ok(Json(organization_json(&state, &organization_id).await?))
}

async fn set_active_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OrganizationSelectInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let organization_id = resolve_organization_id(
        &state,
        &auth,
        input.organization_id.as_deref(),
        input.organization_slug.as_deref(),
    )
    .await?;
    require_workspace(&state, &auth, &organization_id).await?;
    let session_token = auth.session_token.ok_or_else(ApiError::unauthorized)?;
    state
        .database
        .client
        .execute(
            "UPDATE session SET active_organization_id = $1, updated_at = NOW() WHERE token = $2",
            &[&organization_id, &session_token],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(json!({ "success": true })))
}

async fn update_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OrganizationUpdateInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let organization_id = resolve_organization_id(
        &state,
        &auth,
        input.organization_id.as_deref(),
        input.organization_slug.as_deref(),
    )
    .await?;
    require_workspace_permission(&state, &auth, &organization_id, "organization", "update").await?;
    let data = input.data.unwrap_or_default();
    let name = data.name.or(input.name);
    let slug = data.slug.or(input.slug);
    let logo = data.logo.or(input.logo);
    let metadata = data
        .metadata
        .or(input.metadata)
        .map(|value| value.to_string());
    if let Some(name) = name.as_deref() {
        if name.trim().is_empty() || name.chars().count() > 120 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Invalid organization name",
            ));
        }
    }
    if let Some(slug) = slug.as_deref() {
        let slug = slugify_workspace_name(slug);
        let duplicate = state
            .database
            .client
            .query_opt(
                "SELECT id FROM workspace WHERE slug = $1 AND id <> $2 LIMIT 1",
                &[&slug, &organization_id],
            )
            .await
            .map_err(database_error)?;
        if duplicate.is_some() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "Organization slug already exists",
            ));
        }
    }
    let logo_changed = logo.is_some();
    let logo_value = logo.flatten();
    let metadata_changed = metadata.is_some();
    let normalized_name = name.map(|value| value.trim().to_string());
    let normalized_slug = slug.map(|value| slugify_workspace_name(&value));
    state
        .database
        .client
        .execute(
            r#"
              UPDATE workspace
              SET name = COALESCE($1, name),
                  slug = COALESCE($2, slug),
                  logo = CASE WHEN $3 THEN $4 ELSE logo END,
                  metadata = CASE WHEN $5 THEN $6 ELSE metadata END
              WHERE id = $7
            "#,
            &[
                &normalized_name,
                &normalized_slug,
                &logo_changed,
                &logo_value,
                &metadata_changed,
                &metadata,
                &organization_id,
            ],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(organization_json(&state, &organization_id).await?))
}

async fn delete_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OrganizationSelectInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let organization_id = resolve_organization_id(
        &state,
        &auth,
        input.organization_id.as_deref(),
        input.organization_slug.as_deref(),
    )
    .await?;
    require_workspace_permission(&state, &auth, &organization_id, "organization", "delete").await?;
    state
        .database
        .client
        .execute(
            "UPDATE session SET active_organization_id = NULL WHERE active_organization_id = $1",
            &[&organization_id],
        )
        .await
        .map_err(database_error)?;
    let deleted = state
        .database
        .client
        .execute("DELETE FROM workspace WHERE id = $1", &[&organization_id])
        .await
        .map_err(database_error)?;
    if deleted == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Organization not found",
        ));
    }
    Ok(Json(json!({ "success": true })))
}

fn api_key_json(row: &Row, include_key: Option<&str>) -> Result<Value, ApiError> {
    let permissions = row_optional_string(row, "permissions")?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    let metadata = row_optional_string(row, "metadata")?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    let mut output = json!({
        "id": row_string(row, "id")?,
        "name": row_optional_string(row, "name")?,
        "start": row_optional_string(row, "start")?,
        "prefix": row_optional_string(row, "prefix")?,
        "userId": row_optional_string(row, "user_id")?,
        "referenceId": row_optional_string(row, "reference_id")?,
        "enabled": row.try_get::<_, bool>("enabled").unwrap_or(true),
        "permissions": permissions,
        "metadata": metadata,
        "expiresAt": row_optional_string(row, "expires_at")?,
        "createdAt": row_string(row, "created_at")?,
        "updatedAt": row_string(row, "updated_at")?,
    });
    if let Some(key) = include_key {
        output["key"] = Value::String(key.to_string());
    }
    Ok(output)
}

async fn create_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ApiKeyCreateInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let raw_prefix = input.prefix.unwrap_or_else(|| "kaneo".to_string());
    let prefix: String = raw_prefix
        .trim()
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
        })
        .take(32)
        .collect();
    let prefix = if prefix.is_empty() {
        "kaneo".to_string()
    } else {
        prefix
    };
    let raw_key = format!("{}_{}", prefix, Uuid::new_v4().simple());
    let hashed_key = api_key_hash(&raw_key);
    let id = Uuid::new_v4().to_string();
    let name = input.name.map(|value| value.trim().to_string());
    let metadata = input.metadata.map(|value| value.to_string());
    let permissions = input
        .permissions
        .map(|value| serde_json::to_string(&value))
        .transpose()
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.to_string()))?;
    let start: String = raw_key.chars().take(12).collect();
    if let Some(expires_in) = input.expires_in {
        if expires_in <= 0 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "expiresIn must be positive",
            ));
        }
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO apikey
                    (id, config_id, name, start, reference_id, prefix, key, user_id,
                     expires_at, created_at, updated_at, permissions, metadata)
                  VALUES ($1, 'default', $2, $3, $4, $5, $6, $4,
                          NOW() + ($7::bigint * INTERVAL '1 second'), NOW(), NOW(), $8, $9)
                "#,
                &[
                    &id,
                    &name,
                    &start,
                    &auth.user_id,
                    &prefix,
                    &hashed_key,
                    &expires_in,
                    &permissions,
                    &metadata,
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
                  INSERT INTO apikey
                    (id, config_id, name, start, reference_id, prefix, key, user_id,
                     created_at, updated_at, permissions, metadata)
                  VALUES ($1, 'default', $2, $3, $4, $5, $6, $4, NOW(), NOW(), $7, $8)
                "#,
                &[
                    &id,
                    &name,
                    &start,
                    &auth.user_id,
                    &prefix,
                    &hashed_key,
                    &permissions,
                    &metadata,
                ],
            )
            .await
            .map_err(database_error)?;
    }
    let row = state
        .database
        .client
        .query_one(
            r#"
              SELECT id, name, start, prefix, user_id, reference_id, COALESCE(enabled, TRUE) AS enabled,
                     permissions, metadata,
                     to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM apikey WHERE id = $1
            "#,
            &[&id],
        )
        .await
        .map_err(database_error)?;
    let api_key = api_key_json(&row, Some(&raw_key))?;
    Ok(Json(json!({ "key": raw_key, "apiKey": api_key })))
}

async fn list_api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT id, name, start, prefix, user_id, reference_id,
                     COALESCE(enabled, TRUE) AS enabled, permissions, metadata,
                     to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM apikey WHERE COALESCE(reference_id, user_id) = $1 ORDER BY created_at DESC
            "#,
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;
    let keys = rows
        .iter()
        .map(|row| api_key_json(row, None))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({ "apiKeys": keys })))
}

async fn delete_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ApiKeyDeleteInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let deleted = state
        .database
        .client
        .execute(
            "DELETE FROM apikey WHERE id = $1 AND COALESCE(reference_id, user_id) = $2",
            &[&input.key_id, &auth.user_id],
        )
        .await
        .map_err(database_error)?;
    if deleted == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "API key not found"));
    }
    Ok(Json(json!({ "success": true })))
}

async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateUserInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let image_changed = input.image.is_some();
    let image = input.image.flatten();
    state
        .database
        .client
        .execute(
            r#"
              UPDATE "user"
              SET name = COALESCE($1, name),
                  image = CASE WHEN $2 THEN $3 ELSE image END,
                  locale = COALESCE($4, locale),
                  updated_at = NOW()
              WHERE id = $5
            "#,
            &[
                &input.name,
                &image_changed,
                &image,
                &input.locale,
                &auth.user_id,
            ],
        )
        .await
        .map_err(database_error)?;
    let session = session_json(&state, &auth).await?;
    Ok(Json(session.get("user").cloned().unwrap_or(Value::Null)))
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChangePasswordInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    validate_password(&input.new_password)?;
    let row = state
        .database
        .client
        .query_one(
            "SELECT password FROM account WHERE user_id = $1 AND provider_id = 'credential' LIMIT 1",
            &[&auth.user_id],
        )
        .await
        .map_err(database_error)?;
    let password_hash: Option<String> = row.try_get("password").map_err(database_error)?;
    if !password_hash
        .as_deref()
        .is_some_and(|value| bcrypt_verify(&input.current_password, value).unwrap_or(false))
    {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid current password",
        ));
    }
    let password_hash = bcrypt_hash(&input.new_password, 10).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not hash password: {error}"),
        )
    })?;
    state
        .database
        .client
        .execute(
            "UPDATE account SET password = $1, updated_at = NOW() WHERE user_id = $2 AND provider_id = 'credential'",
            &[&password_hash, &auth.user_id],
        )
        .await
        .map_err(database_error)?;
    if input.revoke_other_sessions {
        if let Some(session_token) = auth.session_token.as_deref() {
            state
                .database
                .client
                .execute(
                    "DELETE FROM session WHERE user_id = $1 AND token <> $2",
                    &[&auth.user_id, &session_token],
                )
                .await
                .map_err(database_error)?;
        }
    }
    Ok(Json(json!({ "success": true })))
}

fn device_client_allowed(client_id: &str) -> bool {
    let configured = env::var("DEVICE_AUTH_CLIENT_IDS").ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .any(|value| value == client_id)
    });
    configured.unwrap_or_else(|| matches!(client_id, "kaneo-cli" | "kaneo-mcp"))
}

fn normalize_device_user_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect()
}

fn device_oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

async fn create_device_code(
    State(state): State<AppState>,
    Json(input): Json<DeviceCodeCreateInput>,
) -> Result<Response, ApiError> {
    if !device_client_allowed(input.client_id.trim()) {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "The client is not allowed to use device authorization",
        ));
    }
    let device_code = Uuid::new_v4().simple().to_string();
    let user_code = Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>()
        .to_ascii_uppercase();
    let device_id = Uuid::new_v4().to_string();
    let interval = 5_i32;
    let expires_in = 600_i64;
    state
        .database
        .client
        .execute(
            r#"
              INSERT INTO device_code
                (id, device_code, user_code, created_at, updated_at, expires_at,
                 status, polling_interval, client_id)
              VALUES ($1, $2, $3, NOW(), NOW(), NOW() + ($4::bigint * INTERVAL '1 second'),
                      'pending', $5, $6)
            "#,
            &[
                &device_id,
                &device_code,
                &user_code,
                &expires_in,
                &interval,
                &input.client_id,
            ],
        )
        .await
        .map_err(database_error)?;
    let verification_uri = format!("{}/device", state.client_url.trim_end_matches('/'));
    Ok(Json(json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": format!("{verification_uri}?user_code={user_code}"),
        "interval": interval,
        "expires_in": expires_in,
    }))
    .into_response())
}

async fn claim_device_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let user_code = normalize_device_user_code(
        query
            .get("user_code")
            .map(String::as_str)
            .unwrap_or_default(),
    );
    if user_code.is_empty() {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "A user code is required",
        ));
    }
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT id, device_code, client_id, user_id, status,
                     expires_at > NOW() AS valid
              FROM device_code WHERE user_code = $1 LIMIT 1
            "#,
            &[&user_code],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invalid or expired device code"))?;
    let valid = row.try_get::<_, bool>("valid").unwrap_or(false);
    if !valid {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "The device code has expired",
        ));
    }
    let status: String = row.try_get("status").map_err(database_error)?;
    if status == "denied" || status == "consumed" {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The device code is no longer available",
        ));
    }
    let claimed_user: Option<String> = row.try_get("user_id").map_err(database_error)?;
    if let Some(claimed_user) = claimed_user.as_deref() {
        if claimed_user != auth.user_id {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "This device code belongs to another user",
            ));
        }
    } else {
        state
            .database
            .client
            .execute(
                "UPDATE device_code SET user_id = $1, updated_at = NOW() WHERE id = $2 AND user_id IS NULL",
                &[&auth.user_id, &row.try_get::<_, String>("id").map_err(database_error)?],
            )
            .await
            .map_err(database_error)?;
    }
    Ok(Json(json!({
        "user_code": user_code,
        "client_id": row.try_get::<_, Option<String>>("client_id").map_err(database_error)?,
        "device_code": row.try_get::<_, String>("device_code").map_err(database_error)?,
        "status": status,
    }))
    .into_response())
}

async fn approve_device_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DeviceCodeUserInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let user_code = normalize_device_user_code(&input.user_code);
    let updated = state
        .database
        .client
        .execute(
            r#"
              UPDATE device_code
              SET status = 'approved', user_id = $1, updated_at = NOW()
              WHERE user_code = $2 AND expires_at > NOW()
                AND status = 'pending' AND (user_id IS NULL OR user_id = $1)
            "#,
            &[&auth.user_id, &user_code],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid or expired device code",
        ));
    }
    Ok(Json(json!({ "success": true })))
}

async fn deny_device_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DeviceCodeUserInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let user_code = normalize_device_user_code(&input.user_code);
    let updated = state
        .database
        .client
        .execute(
            r#"
              UPDATE device_code
              SET status = 'denied', updated_at = NOW()
              WHERE user_code = $1 AND expires_at > NOW()
                AND status = 'pending' AND user_id = $2
            "#,
            &[&user_code, &auth.user_id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid or expired device code",
        ));
    }
    Ok(Json(json!({ "success": true })))
}

async fn device_token(
    State(state): State<AppState>,
    Json(input): Json<DeviceTokenInput>,
) -> Result<Response, ApiError> {
    if input.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "The grant type is not supported",
        ));
    }
    if !device_client_allowed(input.client_id.trim()) {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "The client is not allowed to use device authorization",
        ));
    }
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT id, user_id, status, client_id, polling_interval,
                     expires_at > NOW() AS valid,
                     COALESCE(EXTRACT(EPOCH FROM (NOW() - last_polled_at)), 1000000)::double precision AS seconds_since_poll
              FROM device_code WHERE device_code = $1 LIMIT 1
            "#,
            &[&input.device_code],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invalid device code"))?;
    let expected_client: Option<String> = row.try_get("client_id").map_err(database_error)?;
    if expected_client.as_deref() != Some(input.client_id.trim()) {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "The device code was issued to another client",
        ));
    }
    if !row.try_get::<_, bool>("valid").unwrap_or(false) {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "The device code has expired",
        ));
    }
    let status: String = row.try_get("status").map_err(database_error)?;
    if status == "pending" {
        let interval = row.try_get::<_, i32>("polling_interval").unwrap_or(5) as f64;
        let since = row
            .try_get::<_, f64>("seconds_since_poll")
            .unwrap_or(interval);
        if since < interval {
            return Ok(device_oauth_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "Poll interval is too short",
            ));
        }
        let id: String = row.try_get("id").map_err(database_error)?;
        state
            .database
            .client
            .execute(
                "UPDATE device_code SET last_polled_at = NOW(), updated_at = NOW() WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(database_error)?;
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "The user has not approved the device yet",
        ));
    }
    if status == "denied" {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "The device authorization was denied",
        ));
    }
    if status != "approved" {
        return Ok(device_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The device code is no longer available",
        ));
    }
    let user_id: String = row
        .try_get::<_, Option<String>>("user_id")
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "The device has no approved user"))?;
    let (access_token, _) = session_for_user(&state, &user_id, &HeaderMap::new()).await?;
    let id: String = row.try_get("id").map_err(database_error)?;
    state
        .database
        .client
        .execute(
            "UPDATE device_code SET status = 'consumed', updated_at = NOW() WHERE id = $1",
            &[&id],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 2592000,
    }))
    .into_response())
}

struct S3Config {
    endpoint: Url,
    region: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    key_prefix: String,
    force_path_style: bool,
    max_image_upload_bytes: i64,
    presign_ttl_seconds: i64,
}

fn s3_config() -> Result<S3Config, ApiError> {
    let endpoint = env::var("S3_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "S3 uploads are not configured. Set S3_ENDPOINT and S3_BUCKET.",
            )
        })?;
    let bucket = env::var("S3_BUCKET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "S3 uploads are not configured. Set S3_ENDPOINT and S3_BUCKET.",
            )
        })?;
    let access_key_id = env::var("S3_ACCESS_KEY_ID").unwrap_or_default();
    let secret_access_key = env::var("S3_SECRET_ACCESS_KEY").unwrap_or_default();
    if access_key_id.is_empty() != secret_access_key.is_empty() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Incomplete S3 credentials. Set both S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY.",
        ));
    }
    if access_key_id.is_empty() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "S3 credentials are not configured for the Rust runtime.",
        ));
    }
    let endpoint = Url::parse(endpoint.trim()).map_err(|error| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Invalid S3 endpoint: {error}"),
        )
    })?;
    let max_image_upload_bytes = env::var("S3_MAX_IMAGE_UPLOAD_BYTES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10 * 1024 * 1024);
    let presign_ttl_seconds = env::var("S3_PRESIGN_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(300);
    Ok(S3Config {
        endpoint,
        region: env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
        bucket,
        access_key_id,
        secret_access_key,
        key_prefix: env::var("S3_KEY_PREFIX").unwrap_or_default(),
        force_path_style: env::var("S3_FORCE_PATH_STYLE")
            .map(|value| value.trim().to_lowercase() != "false")
            .unwrap_or(true),
        max_image_upload_bytes,
        presign_ttl_seconds,
    })
}

fn aws_percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{:02X}", byte));
        }
    }
    encoded
}

fn aws_encoded_key(key: &str) -> String {
    key.split('/')
        .map(aws_percent_encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn s3_host(url: &Url) -> Result<String, ApiError> {
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "S3 endpoint has no host"))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

fn s3_request_target(config: &S3Config, key: &str) -> Result<(String, String), ApiError> {
    let endpoint_path = config.endpoint.path().trim_end_matches('/');
    let encoded_key = aws_encoded_key(key);
    let (host, path) = if config.force_path_style {
        (
            s3_host(&config.endpoint)?,
            format!(
                "{endpoint_path}/{}{}",
                aws_percent_encode(&config.bucket),
                if encoded_key.is_empty() {
                    String::new()
                } else {
                    format!("/{encoded_key}")
                }
            ),
        )
    } else {
        let endpoint_host = s3_host(&config.endpoint)?;
        (
            format!("{}.{}", aws_percent_encode(&config.bucket), endpoint_host),
            format!("{endpoint_path}/{}", encoded_key),
        )
    };
    let scheme = config.endpoint.scheme();
    Ok((format!("{scheme}://{host}{path}"), path))
}

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8], message: &str) -> Vec<u8> {
    hmac_sha256_bytes(key, message.as_bytes())
}

fn hmac_sha256_bytes(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts arbitrary keys");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn s3_signing_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date);
    let region_key = hmac_sha256(&date_key, region);
    let service_key = hmac_sha256(&region_key, "s3");
    hmac_sha256(&service_key, "aws4_request")
}

fn s3_query_string(pairs: &[(String, String)]) -> String {
    let mut sorted = pairs.to_vec();
    sorted.sort();
    sorted
        .iter()
        .map(|(name, value)| format!("{}={}", aws_percent_encode(name), aws_percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn s3_presigned_put(config: &S3Config, key: &str) -> Result<String, ApiError> {
    let (base_url, path) = s3_request_target(config, key)?;
    let host = Url::parse(&base_url)
        .map_err(|error| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string()))
        .and_then(|url| s3_host(&url))?;
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let short_date = now.format("%Y%m%d").to_string();
    let scope = format!("{short_date}/{}/{}/aws4_request", config.region, "s3");
    let pairs = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        (
            "X-Amz-Credential".to_string(),
            format!("{}/{}", config.access_key_id, scope),
        ),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        (
            "X-Amz-Expires".to_string(),
            config.presign_ttl_seconds.to_string(),
        ),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    let canonical_query = s3_query_string(&pairs);
    let canonical_headers = format!("host:{host}\n");
    let canonical_request =
        format!("PUT\n{path}\n{canonical_query}\n{canonical_headers}\nhost\nUNSIGNED-PAYLOAD");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex_digest(Sha256::digest(canonical_request.as_bytes()).as_ref())
    );
    let signature = hex_digest(&hmac_sha256(
        &s3_signing_key(&config.secret_access_key, &short_date, &config.region),
        &string_to_sign,
    ));
    let mut signed_pairs = pairs;
    signed_pairs.push(("X-Amz-Signature".to_string(), signature));
    Ok(format!("{base_url}?{}", s3_query_string(&signed_pairs)))
}

fn s3_authorization_headers(
    config: &S3Config,
    path: &str,
) -> Result<(String, String, String), ApiError> {
    let host = if config.force_path_style {
        s3_host(&config.endpoint)?
    } else {
        format!(
            "{}.{}",
            aws_percent_encode(&config.bucket),
            s3_host(&config.endpoint)?
        )
    };
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let short_date = now.format("%Y%m%d").to_string();
    let scope = format!("{short_date}/{}/{}/aws4_request", config.region, "s3");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:{amz_date}\n");
    let canonical_request =
        format!("GET\n{path}\n\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex_digest(Sha256::digest(canonical_request.as_bytes()).as_ref())
    );
    let signature = hex_digest(&hmac_sha256(
        &s3_signing_key(&config.secret_access_key, &short_date, &config.region),
        &string_to_sign,
    ));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
        config.access_key_id, scope
    );
    Ok((host, amz_date, authorization))
}

fn validate_task_image_input(
    config: &S3Config,
    content_type: &str,
    size: i64,
) -> Result<(), ApiError> {
    if content_type.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "A valid content type is required",
        ));
    }
    if size <= 0 || size > config.max_image_upload_bytes {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "Upload must be greater than zero and no larger than {} bytes",
                config.max_image_upload_bytes
            ),
        ));
    }
    Ok(())
}

fn sanitize_asset_path_segment(value: &str) -> String {
    let mut output = String::new();
    let mut last_dash = false;
    for character in value.to_lowercase().chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            output.push(character);
            last_dash = false;
        } else if !last_dash {
            output.push('-');
            last_dash = true;
        }
    }
    let trimmed = output.trim_matches('-');
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

fn task_asset_key(
    config: &S3Config,
    workspace_id: &str,
    project_id: &str,
    task_id: &str,
    surface: &str,
    filename: &str,
) -> String {
    let surface_folder = if surface == "comment" {
        "comments"
    } else {
        "descriptions"
    };
    let extension = filename
        .rsplit_once('.')
        .map(|(_, extension)| sanitize_asset_path_segment(extension))
        .filter(|extension| !extension.is_empty() && extension != "file");
    let stem = filename
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(filename);
    let base = sanitize_asset_path_segment(stem)
        .chars()
        .take(64)
        .collect::<String>();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let filename = match extension {
        Some(extension) => format!(
            "{base}-{timestamp}-{}.{}",
            Uuid::new_v4().simple(),
            extension
        ),
        None => format!("{base}-{timestamp}-{}", Uuid::new_v4().simple()),
    };
    let raw = format!(
        "workspace/{}/project/{}/task/{}/{}/{}",
        sanitize_asset_path_segment(workspace_id),
        sanitize_asset_path_segment(project_id),
        sanitize_asset_path_segment(task_id),
        surface_folder,
        filename
    );
    let prefix = config.key_prefix.trim_end_matches('/');
    if prefix.is_empty() {
        raw
    } else {
        format!("{prefix}/{raw}")
    }
}

async fn task_upload_context(
    state: &AppState,
    task_id: &str,
) -> Result<(String, String, String), ApiError> {
    state
        .database
        .client
        .query_opt(
            r#"
              SELECT t.id AS task_id, t.project_id, p.workspace_id
              FROM task t INNER JOIN project p ON p.id = t.project_id
              WHERE t.id = $1 LIMIT 1
            "#,
            &[&task_id],
        )
        .await
        .map_err(database_error)?
        .map(|row| {
            Ok((
                row_string(&row, "task_id")?,
                row_string(&row, "project_id")?,
                row_string(&row, "workspace_id")?,
            ))
        })
        .transpose()?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Task not found"))
}

async fn create_task_image_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<TaskImageUploadInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_task(&state, &headers, &id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "task", "update").await?;
    if input.surface != "description" && input.surface != "comment" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid upload surface",
        ));
    }
    let config = s3_config()?;
    validate_task_image_input(&config, &input.content_type, input.size)?;
    let (task_id, project_id, workspace_id) = task_upload_context(&state, &id).await?;
    let key = task_asset_key(
        &config,
        &workspace_id,
        &project_id,
        &task_id,
        &input.surface,
        &input.filename,
    );
    let upload_url = s3_presigned_put(&config, &key)?;
    Ok(Json(json!({
        "key": key,
        "uploadUrl": upload_url,
        "headers": { "Content-Type": input.content_type },
    })))
}

async fn finalize_task_image_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<TaskImageFinalizeInput>,
) -> Result<Json<Value>, ApiError> {
    let (auth, workspace_id) = auth_for_task(&state, &headers, &id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "task", "update").await?;
    if input.surface != "description" && input.surface != "comment" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid upload surface",
        ));
    }
    let config = s3_config()?;
    validate_task_image_input(&config, &input.content_type, input.size)?;
    let (task_id, project_id, workspace_id) = task_upload_context(&state, &id).await?;
    let prefix = format!(
        "{}/workspace/{}/project/{}/task/{}/{}/",
        config.key_prefix.trim_end_matches('/'),
        sanitize_asset_path_segment(&workspace_id),
        sanitize_asset_path_segment(&project_id),
        sanitize_asset_path_segment(&task_id),
        if input.surface == "comment" {
            "comments"
        } else {
            "descriptions"
        },
    );
    let expected_prefix = prefix.trim_start_matches('/').trim_start_matches('/');
    let normalized_key = input.key.trim();
    if !normalized_key.starts_with(expected_prefix) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Image upload key does not match the task context",
        ));
    }
    let kind = if input.content_type.to_lowercase().starts_with("image/") {
        "image"
    } else {
        "attachment"
    };
    let existing = state
        .database
        .client
        .query_opt(
            "SELECT id FROM asset WHERE object_key = $1 LIMIT 1",
            &[&normalized_key],
        )
        .await
        .map_err(database_error)?;
    let asset_id = if let Some(row) = existing {
        let asset_id = row_string(&row, "id")?;
        state
            .database
            .client
            .execute(
                r#"
                  UPDATE asset
                  SET workspace_id = $1, project_id = $2, task_id = $3,
                      filename = $4, mime_type = $5, size = $6, kind = $7,
                      surface = $8, created_by = $9
                  WHERE id = $10
                "#,
                &[
                    &workspace_id,
                    &project_id,
                    &task_id,
                    &input.filename,
                    &input.content_type,
                    &input.size,
                    &kind,
                    &input.surface,
                    &auth.user_id,
                    &asset_id,
                ],
            )
            .await
            .map_err(database_error)?;
        asset_id
    } else {
        let asset_id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO asset
                    (id, workspace_id, project_id, task_id, object_key, filename,
                     mime_type, size, kind, surface, created_by, created_at)
                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
                "#,
                &[
                    &asset_id,
                    &workspace_id,
                    &project_id,
                    &task_id,
                    &normalized_key,
                    &input.filename,
                    &input.content_type,
                    &input.size,
                    &kind,
                    &input.surface,
                    &auth.user_id,
                ],
            )
            .await
            .map_err(database_error)?;
        asset_id
    };
    Ok(Json(json!({
        "id": asset_id,
        "url": format!("{}/asset/{asset_id}", state.api_base_url),
    })))
}

fn asset_content_disposition(filename: &str, inline: bool) -> String {
    let normalized = filename.replace(['\r', '\n', '"'], "").trim().to_string();
    let safe = if normalized.is_empty() {
        "file"
    } else {
        &normalized
    };
    let ascii = safe
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>()
        .replace(['/', '\\'], "-");
    let disposition = if inline { "inline" } else { "attachment" };
    format!(
        "{disposition}; filename=\"{}\"; filename*=UTF-8''{}",
        if ascii.is_empty() { "file" } else { &ascii },
        aws_percent_encode(safe)
    )
}

async fn get_asset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT a.object_key, a.mime_type, a.filename, a.workspace_id,
                     COALESCE(p.is_public, FALSE) AS is_public
              FROM asset a INNER JOIN project p ON p.id = a.project_id
              WHERE a.id = $1 LIMIT 1
            "#,
            &[&id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Asset not found"))?;
    let is_public = row.try_get::<_, bool>("is_public").unwrap_or(false);
    match authenticate(&state, &headers).await {
        Ok(auth) => require_workspace(&state, &auth, &row_string(&row, "workspace_id")?).await?,
        Err(error) if is_public && error.status == StatusCode::UNAUTHORIZED => {}
        Err(error) => return Err(error),
    }
    let config = s3_config()?;
    let key = row_string(&row, "object_key")?;
    let (url, path) = s3_request_target(&config, &key)?;
    let (host, amz_date, authorization) = s3_authorization_headers(&config, &path)?;
    let object = state
        .http
        .get(url)
        .header("Host", host)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .header("Authorization", authorization)
        .send()
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("S3 request failed: {error}"),
            )
        })?;
    if object.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Asset object not found",
        ));
    }
    if !object.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("S3 returned status {}", object.status()),
        ));
    }
    let object_headers = object.headers().clone();
    let body = object.bytes().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Could not read asset object: {error}"),
        )
    })?;
    let body_length = body.len();
    let fallback_content_type: String = row.try_get("mime_type").unwrap_or_default();
    let stored_content_type = object_headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(fallback_content_type.as_str())
        .split(';')
        .next()
        .unwrap_or("application/octet-stream")
        .trim()
        .to_string();
    let inline = matches!(
        stored_content_type.as_str(),
        "image/apng"
            | "image/avif"
            | "image/gif"
            | "image/heic"
            | "image/heif"
            | "image/jpeg"
            | "image/jpg"
            | "image/png"
            | "image/webp"
    );
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=120"),
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&asset_content_disposition(
            &row_string(&row, "filename")?,
            inline,
        ))
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?,
    );
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(if inline {
            &stored_content_type
        } else {
            "application/octet-stream"
        })
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?,
    );
    response_headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response_headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&body_length.to_string())
            .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?,
    );
    for (source, target) in [
        ("etag", header::ETAG),
        ("last-modified", header::LAST_MODIFIED),
    ] {
        if let Some(value) = object_headers.get(source).cloned() {
            response_headers.insert(target, value);
        }
    }
    Ok(response)
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

async fn get_active_member(
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
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT m.id AS member_id, m.workspace_id AS organization_id,
                     m.user_id, m.role,
                     to_char(m.joined_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS member_created_at,
                     u.name AS user_name, u.email AS user_email, u.image AS user_image
              FROM workspace_member m
              INNER JOIN "user" u ON u.id = m.user_id
              WHERE m.workspace_id = $1 AND m.user_id = $2
              LIMIT 1
            "#,
            &[&organization_id, &auth.user_id],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(
        row.as_ref()
            .map(organization_member_json)
            .transpose()?
            .unwrap_or(Value::Null),
    ))
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

fn invitation_json(row: &Row) -> Result<Value, ApiError> {
    Ok(json!({
        "id": row_string(row, "invitation_id")?,
        "organizationId": row_string(row, "organization_id")?,
        "email": row_string(row, "email")?,
        "role": row_optional_string(row, "role")?,
        "status": row_string(row, "status")?,
        "inviterId": row_string(row, "inviter_id")?,
        "expiresAt": row_string(row, "expires_at")?,
        "createdAt": row_string(row, "created_at")?,
        "organization": {
            "id": row_string(row, "organization_id")?,
            "name": row_optional_string(row, "organization_name")?,
        },
    }))
}

async fn invitation_row(state: &AppState, invitation_id: &str) -> Result<Row, ApiError> {
    state
        .database
        .client
        .query_opt(
            r#"
              SELECT i.id AS invitation_id, i.workspace_id AS organization_id,
                     i.email, i.role, i.status, i.inviter_id,
                     to_char(i.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     to_char(i.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     w.name AS organization_name
              FROM invitation i
              INNER JOIN workspace w ON w.id = i.workspace_id
              WHERE i.id = $1 LIMIT 1
            "#,
            &[&invitation_id],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Invitation not found"))
}

async fn current_user_email(state: &AppState, auth: &AuthContext) -> Result<String, ApiError> {
    state
        .database
        .client
        .query_one("SELECT email FROM \"user\" WHERE id = $1", &[&auth.user_id])
        .await
        .map_err(database_error)?
        .try_get("email")
        .map_err(database_error)
}

async fn list_invitations(
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
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT i.id AS invitation_id, i.workspace_id AS organization_id,
                     i.email, i.role, i.status, i.inviter_id,
                     to_char(i.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     to_char(i.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     w.name AS organization_name
              FROM invitation i INNER JOIN workspace w ON w.id = i.workspace_id
              WHERE i.workspace_id = $1 ORDER BY i.created_at ASC
            "#,
            &[&organization_id],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(Value::Array(
        rows.iter()
            .map(invitation_json)
            .collect::<Result<Vec<_>, _>>()?,
    )))
}

async fn list_user_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let email = current_user_email(&state, &auth).await?;
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT i.id AS invitation_id, i.workspace_id AS organization_id,
                     i.email, i.role, i.status, i.inviter_id,
                     to_char(i.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
                     to_char(i.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     w.name AS organization_name
              FROM invitation i INNER JOIN workspace w ON w.id = i.workspace_id
              WHERE lower(i.email) = lower($1) AND i.status = 'pending'
                AND i.expires_at > NOW()
              ORDER BY i.created_at ASC
            "#,
            &[&email],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(Value::Array(
        rows.iter()
            .map(invitation_json)
            .collect::<Result<Vec<_>, _>>()?,
    )))
}

async fn get_organization_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let invitation_id = query
        .get("id")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invitation id is required"))?;
    let row = invitation_row(&state, invitation_id).await?;
    require_workspace(&state, &auth, &row_string(&row, "organization_id")?).await?;
    Ok(Json(invitation_json(&row)?))
}

async fn invite_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<InviteMemberInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace_permission(&state, &auth, &input.organization_id, "member", "create").await?;
    let email = normalize_email(&input.email)?;
    let role = input.role.unwrap_or_else(|| "member".to_string());
    if role.trim().is_empty() || role.len() > 64 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid member role",
        ));
    }
    let existing = state
        .database
        .client
        .query_opt(
            "SELECT id FROM invitation WHERE workspace_id = $1 AND lower(email) = lower($2) AND status = 'pending' LIMIT 1",
            &[&input.organization_id, &email],
        )
        .await
        .map_err(database_error)?;
    let invitation_id = if let Some(row) = existing {
        let id: String = row.try_get("id").map_err(database_error)?;
        if !input.resend.unwrap_or(false) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "An invitation for this email already exists",
            ));
        }
        state
            .database
            .client
            .execute(
                "UPDATE invitation SET role = $1, expires_at = NOW() + INTERVAL '7 days', inviter_id = $2 WHERE id = $3",
                &[&role, &auth.user_id, &id],
            )
            .await
            .map_err(database_error)?;
        id
    } else {
        let id = Uuid::new_v4().to_string();
        state
            .database
            .client
            .execute(
                r#"
                  INSERT INTO invitation
                    (id, workspace_id, email, role, status, expires_at, created_at, inviter_id)
                  VALUES ($1, $2, $3, $4, 'pending', NOW() + INTERVAL '7 days', NOW(), $5)
                "#,
                &[&id, &input.organization_id, &email, &role, &auth.user_id],
            )
            .await
            .map_err(database_error)?;
        id
    };
    let row = invitation_row(&state, &invitation_id).await?;
    Ok(Json(invitation_json(&row)?))
}

async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OrganizationMemberInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let organization_id = input
        .organization_id
        .as_deref()
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Organization id is required"))?;
    require_workspace_permission(&state, &auth, organization_id, "member", "delete").await?;
    let member_id_or_email = input
        .member_id_or_email
        .or(input.member_id)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Member id is required"))?;
    let row = state
        .database
        .client
        .query_opt(
            r#"
              SELECT m.id, m.user_id, m.role
              FROM workspace_member m INNER JOIN "user" u ON u.id = m.user_id
              WHERE m.workspace_id = $1
                AND (m.id = $2 OR m.user_id = $2 OR lower(u.email) = lower($2))
              LIMIT 1
            "#,
            &[&organization_id, &member_id_or_email],
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Workspace member not found"))?;
    let member_role: String = row.try_get("role").map_err(database_error)?;
    if member_role == "owner" {
        let owner_count = state
            .database
            .client
            .query_one(
                "SELECT COUNT(*)::bigint AS count FROM workspace_member WHERE workspace_id = $1 AND role = 'owner'",
                &[&organization_id],
            )
            .await
            .map_err(database_error)?
            .try_get::<_, i64>("count")
            .map_err(database_error)?;
        if owner_count <= 1 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "The last workspace owner cannot be removed",
            ));
        }
    }
    let member_id: String = row.try_get("id").map_err(database_error)?;
    state
        .database
        .client
        .execute("DELETE FROM workspace_member WHERE id = $1", &[&member_id])
        .await
        .map_err(database_error)?;
    Ok(Json(json!({ "success": true })))
}

async fn update_member_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OrganizationMemberInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let organization_id = input
        .organization_id
        .as_deref()
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Organization id is required"))?;
    require_workspace_permission(&state, &auth, organization_id, "member", "update").await?;
    let member_id = input
        .member_id
        .as_deref()
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Member id is required"))?;
    let role = input
        .role
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Member role is required"))?;
    if role.len() > 64 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid member role",
        ));
    }
    let updated = state
        .database
        .client
        .execute(
            "UPDATE workspace_member SET role = $1 WHERE id = $2 AND workspace_id = $3",
            &[&role, &member_id, &organization_id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Workspace member not found",
        ));
    }
    Ok(Json(json!({ "success": true })))
}

async fn accept_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<InvitationActionInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let email = current_user_email(&state, &auth).await?;
    let row = invitation_row(&state, &input.invitation_id).await?;
    let organization_id = row_string(&row, "organization_id")?;
    let invitation_email = row_string(&row, "email")?;
    if !email.eq_ignore_ascii_case(&invitation_email) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Invitation email does not match the signed-in user",
        ));
    }
    if row_string(&row, "status")? != "pending" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invitation is no longer pending",
        ));
    }
    let role = row_optional_string(&row, "role")?.unwrap_or_else(|| "member".to_string());
    let existing = state
        .database
        .client
        .query_opt(
            "SELECT id FROM workspace_member WHERE workspace_id = $1 AND user_id = $2 LIMIT 1",
            &[&organization_id, &auth.user_id],
        )
        .await
        .map_err(database_error)?;
    if existing.is_none() {
        state
            .database
            .client
            .execute(
                "INSERT INTO workspace_member (id, workspace_id, user_id, role, joined_at) VALUES ($1, $2, $3, $4, NOW())",
                &[&Uuid::new_v4().to_string(), &organization_id, &auth.user_id, &role],
            )
            .await
            .map_err(database_error)?;
    }
    state
        .database
        .client
        .execute(
            "UPDATE invitation SET status = 'accepted' WHERE id = $1",
            &[&input.invitation_id],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(json!({ "success": true })))
}

async fn reject_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<InvitationActionInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let email = current_user_email(&state, &auth).await?;
    let row = invitation_row(&state, &input.invitation_id).await?;
    if !email.eq_ignore_ascii_case(&row_string(&row, "email")?) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Invitation email does not match the signed-in user",
        ));
    }
    let updated = state
        .database
        .client
        .execute(
            "UPDATE invitation SET status = 'rejected' WHERE id = $1 AND status = 'pending'",
            &[&input.invitation_id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invitation is no longer pending",
        ));
    }
    Ok(Json(json!({ "success": true })))
}

async fn cancel_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<InvitationActionInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    let row = invitation_row(&state, &input.invitation_id).await?;
    require_workspace_permission(
        &state,
        &auth,
        &row_string(&row, "organization_id")?,
        "invitation",
        "cancel",
    )
    .await?;
    let updated = state
        .database
        .client
        .execute(
            "UPDATE invitation SET status = 'canceled' WHERE id = $1 AND status = 'pending'",
            &[&input.invitation_id],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invitation is no longer pending",
        ));
    }
    Ok(Json(json!({ "success": true })))
}

async fn list_roles(
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
    let rows = state
        .database
        .client
        .query(
            r#"
              SELECT id, workspace_id, role, permission,
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
                     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
              FROM workspace_role WHERE workspace_id = $1 ORDER BY role ASC
            "#,
            &[&organization_id],
        )
        .await
        .map_err(database_error)?;
    Ok(Json(Value::Array(
        rows.into_iter()
            .map(|row| {
                Ok(json!({
                    "id": row_string(&row, "id")?,
                    "organizationId": row_string(&row, "workspace_id")?,
                    "role": row_string(&row, "role")?,
                    "permission": row_string(&row, "permission")?,
                    "createdAt": row_string(&row, "created_at")?,
                    "updatedAt": row_string(&row, "updated_at")?,
                }))
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
    )))
}

async fn create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RoleCreateInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace_permission(&state, &auth, &input.organization_id, "ac", "create").await?;
    let role = input.role.trim().to_string();
    if role.is_empty() || role.len() > 64 || role == "owner" {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Invalid role name"));
    }
    let permission = serde_json::to_string(&input.permission).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid role permissions: {error}"),
        )
    })?;
    let inserted = state
        .database
        .client
        .execute(
            "INSERT INTO workspace_role (id, workspace_id, role, permission, created_at, updated_at) SELECT $1, $2, $3, $4, NOW(), NOW() WHERE NOT EXISTS (SELECT 1 FROM workspace_role WHERE workspace_id = $2 AND role = $3)",
            &[&Uuid::new_v4().to_string(), &input.organization_id, &role, &permission],
        )
        .await
        .map_err(database_error)?;
    if inserted == 0 {
        return Err(ApiError::new(StatusCode::CONFLICT, "Role already exists"));
    }
    Ok(Json(json!({ "success": true })))
}

async fn update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RoleUpdateInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace_permission(&state, &auth, &input.organization_id, "ac", "update").await?;
    let permission = input
        .data
        .and_then(|data| data.permission)
        .or(input.permission)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Role permissions are required"))?;
    let permission = serde_json::to_string(&permission)
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.to_string()))?;
    let updated = state
        .database
        .client
        .execute(
            "UPDATE workspace_role SET permission = $1, updated_at = NOW() WHERE workspace_id = $2 AND role = $3",
            &[&permission, &input.organization_id, &input.role_name],
        )
        .await
        .map_err(database_error)?;
    if updated == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Role not found"));
    }
    Ok(Json(json!({ "success": true })))
}

async fn delete_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RoleDeleteInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace_permission(&state, &auth, &input.organization_id, "ac", "delete").await?;
    if matches!(
        input.role_name.as_str(),
        "owner" | "admin" | "member" | "viewer"
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Default roles cannot be deleted",
        ));
    }
    let assigned = state
        .database
        .client
        .query_one(
            "SELECT COUNT(*)::bigint AS count FROM workspace_member WHERE workspace_id = $1 AND role = $2",
            &[&input.organization_id, &input.role_name],
        )
        .await
        .map_err(database_error)?
        .try_get::<_, i64>("count")
        .map_err(database_error)?;
    if assigned > 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Role is still assigned to workspace members",
        ));
    }
    let deleted = state
        .database
        .client
        .execute(
            "DELETE FROM workspace_role WHERE workspace_id = $1 AND role = $2",
            &[&input.organization_id, &input.role_name],
        )
        .await
        .map_err(database_error)?;
    if deleted == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Role not found"));
    }
    Ok(Json(json!({ "success": true })))
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
        "TASK_COMMENT_CREATED",
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
        "TASK_COMMENT_CREATED",
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
        ..Default::default()
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

fn billing_product_id(plan: &str, interval: &str) -> Option<String> {
    let key = match (plan, interval) {
        ("personal", "monthly") => "CREEM_PRODUCT_PERSONAL_MONTHLY",
        ("personal", "annual") => "CREEM_PRODUCT_PERSONAL_ANNUAL",
        ("team", "monthly") => "CREEM_PRODUCT_TEAM_MONTHLY",
        ("team", "annual") => "CREEM_PRODUCT_TEAM_ANNUAL",
        _ => return None,
    };
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

fn billing_plan_for_product(product_id: &str) -> Option<(&'static str, &'static str)> {
    [
        ("personal", "monthly"),
        ("personal", "annual"),
        ("team", "monthly"),
        ("team", "annual"),
    ]
    .into_iter()
    .find(|(plan, interval)| billing_product_id(plan, interval).as_deref() == Some(product_id))
}

fn billing_api_base_url() -> String {
    if let Some(value) = env::var("CREEM_API_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        return value.trim_end_matches('/').to_string();
    }
    if env_true("CREEM_TEST_MODE") {
        "https://test-api.creem.io".to_string()
    } else {
        "https://api.creem.io".to_string()
    }
}

async fn creem_request(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    payload: Option<Value>,
) -> Result<Value, ApiError> {
    let api_key = env::var("CREEM_API_KEY").map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Billing is not configured with a Creem API key",
        )
    })?;
    let url = format!("{}{}", billing_api_base_url(), path);
    let mut request = state
        .http
        .request(method, url)
        .header("x-api-key", api_key)
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(20));
    if let Some(payload) = payload {
        request = request
            .header("Content-Type", "application/json")
            .json(&payload);
    }
    let response = request.send().await.map_err(|error| {
        eprintln!("billing: Creem request failed: {error}");
        ApiError::new(StatusCode::BAD_GATEWAY, "Billing provider request failed")
    })?;
    let status = StatusCode::from_u16(response.status().as_u16()).map_err(database_error)?;
    let body = response.bytes().await.map_err(|error| {
        eprintln!("billing: could not read Creem response: {error}");
        ApiError::new(StatusCode::BAD_GATEWAY, "Billing provider request failed")
    })?;
    if !status.is_success() {
        eprintln!("billing: Creem returned {status}");
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "Billing provider request failed",
        ));
    }
    if body.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&body).map_err(|error| {
        eprintln!("billing: Creem returned invalid JSON: {error}");
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "Billing provider returned invalid JSON",
        )
    })
}

fn billing_trial_days() -> i32 {
    env::var("BILLING_TRIAL_DAYS")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|days| *days >= 0)
        .unwrap_or(14)
}

async fn ensure_workspace_billing(state: &AppState, workspace_id: &str) -> Result<(), ApiError> {
    let workspace_exists = state
        .database
        .client
        .query_opt(
            "SELECT created_at FROM workspace WHERE id = $1 LIMIT 1",
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    if workspace_exists.is_none() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Workspace not found"));
    }

    let existing = state
        .database
        .client
        .query_opt(
            "SELECT id FROM workspace_billing WHERE workspace_id = $1 LIMIT 1",
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    if existing.is_some() {
        return Ok(());
    }

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
    Ok(())
}

async fn get_workspace_billing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &workspace_id).await?;
    ensure_workspace_billing(&state, &workspace_id).await?;

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

async fn require_billing_manager(
    state: &AppState,
    headers: &HeaderMap,
    workspace_id: &str,
) -> Result<AuthContext, ApiError> {
    let auth = authenticate(state, headers).await?;
    require_workspace(state, &auth, workspace_id).await?;
    if auth.is_admin() {
        return Ok(auth);
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
        .and_then(|row| row.try_get::<_, String>("role").ok());
    if !matches!(role.as_deref(), Some("owner" | "admin")) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Only workspace owners and admins can manage billing",
        ));
    }
    Ok(auth)
}

async fn create_billing_checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(input): Json<BillingCheckoutInput>,
) -> Result<Json<Value>, ApiError> {
    let auth = require_billing_manager(&state, &headers, &workspace_id).await?;
    if !matches!(input.plan.as_str(), "personal" | "team")
        || !matches!(input.interval.as_str(), "monthly" | "annual")
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Unknown plan or billing interval",
        ));
    }
    if !billing_is_enabled() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Billing is not enabled",
        ));
    }
    let product_id = billing_product_id(&input.plan, &input.interval)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Unknown plan"))?;
    ensure_workspace_billing(&state, &workspace_id).await?;
    let billing = state
        .database
        .client
        .query_one(
            "SELECT status FROM workspace_billing WHERE workspace_id = $1 LIMIT 1",
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    if billing
        .try_get::<_, Option<String>>("status")
        .map_err(database_error)?
        .as_deref()
        == Some("active")
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Workspace already has an active subscription",
        ));
    }
    let units = if input.plan == "team" {
        state
            .database
            .client
            .query_one(
                "SELECT GREATEST(1, COUNT(*)::int) AS units FROM workspace_member WHERE workspace_id = $1",
                &[&workspace_id],
            )
            .await
            .map_err(database_error)?
            .try_get::<_, i32>("units")
            .map_err(database_error)?
    } else {
        1
    };
    let email = current_user_email(&state, &auth).await?;
    let success_url = format!(
        "{}/dashboard/settings/workspace/billing?checkout=success",
        state.client_url.trim_end_matches('/')
    );
    let checkout = creem_request(
        &state,
        reqwest::Method::POST,
        "/v1/checkouts",
        Some(json!({
            "product_id": product_id,
            "units": units,
            "success_url": success_url,
            "request_id": Uuid::new_v4().to_string(),
            "customer": { "email": email },
            "metadata": {
                "workspaceId": workspace_id,
                "plan": input.plan,
                "interval": input.interval,
            },
        })),
    )
    .await?;
    let checkout_url = checkout
        .get("checkout_url")
        .or_else(|| checkout.get("checkoutUrl"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "Billing provider returned no checkout URL",
            )
        })?;
    Ok(Json(json!({ "checkoutUrl": checkout_url })))
}

async fn create_billing_portal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _auth = require_billing_manager(&state, &headers, &workspace_id).await?;
    let billing = state
        .database
        .client
        .query_opt(
            "SELECT creem_customer_id FROM workspace_billing WHERE workspace_id = $1 LIMIT 1",
            &[&workspace_id],
        )
        .await
        .map_err(database_error)?;
    let Some(customer_id) = billing
        .as_ref()
        .and_then(|row| row_optional_string(row, "creem_customer_id").ok().flatten())
    else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "No billing customer exists for this workspace yet",
        ));
    };
    if !billing_is_enabled() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Billing is not enabled",
        ));
    }
    let links = creem_request(
        &state,
        reqwest::Method::POST,
        "/v1/customers/billing",
        Some(json!({ "customer_id": customer_id })),
    )
    .await?;
    let portal_url = links
        .get("customer_portal_link")
        .or_else(|| links.get("customerPortalLink"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "Billing provider returned no portal URL",
            )
        })?;
    Ok(Json(json!({ "portalUrl": portal_url })))
}

fn billing_id_value(object: &Value, key: &str) -> Option<String> {
    match object.get(key) {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
        Some(Value::Object(value)) => value
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn billing_string_value(object: &Value, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn billing_metadata_value(object: &Value, key: &str) -> Option<String> {
    object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn billing_timestamp_value(object: &Value, key: &str) -> Option<String> {
    let raw = billing_string_value(object, key)?;
    chrono::DateTime::parse_from_rfc3339(&raw)
        .ok()
        .map(|value| value.naive_utc().to_string())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn verify_creem_webhook(headers: &HeaderMap, secret: &str, payload: &[u8]) -> bool {
    let standard_headers = headers
        .get("webhook-id")
        .and_then(|value| value.to_str().ok())
        .zip(
            headers
                .get("webhook-timestamp")
                .and_then(|value| value.to_str().ok()),
        )
        .zip(
            headers
                .get("webhook-signature")
                .and_then(|value| value.to_str().ok()),
        );
    if let Some(((webhook_id, timestamp), signature)) = standard_headers {
        let Ok(timestamp) = timestamp.parse::<i64>() else {
            return false;
        };
        if (Utc::now().timestamp() - timestamp).abs() > 5 * 60 {
            return false;
        }
        let secret_value = secret.strip_prefix("whsec_").unwrap_or(secret);
        let Ok(secret_bytes) = base64::engine::general_purpose::STANDARD.decode(secret_value)
        else {
            return false;
        };
        let mut signed_payload = format!("{webhook_id}.{timestamp}.").into_bytes();
        signed_payload.extend_from_slice(payload);
        let expected = base64::engine::general_purpose::STANDARD
            .encode(hmac_sha256_bytes(&secret_bytes, &signed_payload));
        return signature.split_whitespace().any(|value| {
            let Some(value) = value.strip_prefix("v1,") else {
                return false;
            };
            constant_time_equal(value.as_bytes(), expected.as_bytes())
        });
    }

    let Some(signature) = headers
        .get("creem-signature")
        .or_else(|| headers.get("x-creem-signature"))
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let provided = signature
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or(signature.trim())
        .to_ascii_lowercase();
    let expected = hex_digest(&hmac_sha256_bytes(secret.as_bytes(), payload));
    constant_time_equal(provided.as_bytes(), expected.as_bytes())
}

async fn billing_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    if !billing_is_enabled() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Not found"));
    }
    let secret = env::var("CREEM_WEBHOOK_SECRET")
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "Not found"))?;
    if !verify_creem_webhook(&headers, &secret, &body) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Invalid signature"));
    }
    let payload: Value = serde_json::from_slice(&body).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid webhook payload: {error}"),
        )
    })?;
    let event_type = payload
        .get("type")
        .or_else(|| payload.get("eventType"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invalid webhook payload"))?
        .to_string();
    let data = payload
        .get("data")
        .or_else(|| payload.get("object"))
        .cloned()
        .unwrap_or(Value::Null);
    let event_id = payload
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    if let Some(event_id) = event_id.as_deref() {
        let inserted = state
            .database
            .client
            .execute(
                "INSERT INTO billing_event (id, event_type) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING",
                &[&event_id, &event_type],
            )
            .await
            .map_err(database_error)?;
        if inserted == 0 {
            return Ok(Json(json!({ "processed": false, "duplicate": true })));
        }
    }

    if event_type == "checkout.completed" {
        let subscription = data.get("subscription").unwrap_or(&Value::Null);
        let workspace_id = billing_metadata_value(&data, "workspaceId")
            .or_else(|| billing_metadata_value(subscription, "workspaceId"));
        let Some(workspace_id) = workspace_id else {
            eprintln!("billing: checkout.completed without workspaceId");
            return Ok(Json(json!({ "processed": false, "duplicate": false })));
        };
        ensure_workspace_billing(&state, &workspace_id).await?;
        let product_id = billing_id_value(&data, "product")
            .or_else(|| billing_id_value(subscription, "product"));
        let customer_id = billing_id_value(&data, "customer")
            .or_else(|| billing_id_value(subscription, "customer"));
        let subscription_id = billing_id_value(&data, "subscription");
        let mapped = product_id.as_deref().and_then(billing_plan_for_product);
        let plan = mapped.map(|(plan, _)| plan.to_string());
        let interval = mapped.map(|(_, interval)| interval.to_string());
        let status =
            billing_string_value(subscription, "status").or_else(|| Some("active".to_string()));
        state
            .database
            .client
            .execute(
                r#"
                  UPDATE workspace_billing
                  SET creem_customer_id = $1,
                      creem_subscription_id = $2,
                      creem_product_id = $3,
                      plan = $4,
                      billing_interval = $5,
                      status = $6,
                      updated_at = NOW()
                  WHERE workspace_id = $7
                "#,
                &[
                    &customer_id,
                    &subscription_id,
                    &product_id,
                    &plan,
                    &interval,
                    &status,
                    &workspace_id,
                ],
            )
            .await
            .map_err(database_error)?;
        return Ok(Json(json!({ "processed": true, "duplicate": false })));
    }

    if event_type.starts_with("subscription.") {
        let Some(subscription_id) = billing_id_value(&data, "id") else {
            return Ok(Json(json!({ "processed": false, "duplicate": false })));
        };
        let product_id = billing_id_value(&data, "product");
        let mapped = product_id.as_deref().and_then(billing_plan_for_product);
        let plan = mapped.map(|(plan, _)| plan.to_string());
        let interval = mapped.map(|(_, interval)| interval.to_string());
        let status = billing_string_value(&data, "status").or_else(|| {
            Some(
                match event_type.as_str() {
                    "subscription.active" | "subscription.paid" => "active",
                    "subscription.trialing" => "trialing",
                    "subscription.scheduled_cancel" => "scheduled_cancel",
                    "subscription.canceled" => "canceled",
                    "subscription.past_due" => "past_due",
                    "subscription.expired" => "expired",
                    "subscription.paused" => "paused",
                    _ => return None,
                }
                .to_string(),
            )
        });
        let current_period_end = billing_timestamp_value(&data, "current_period_end_date")
            .or_else(|| billing_timestamp_value(&data, "currentPeriodEndDate"));
        let canceled_at = billing_timestamp_value(&data, "canceled_at")
            .or_else(|| billing_timestamp_value(&data, "canceledAt"));
        let seats = data
            .get("items")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get("units"))
            .and_then(Value::as_i64)
            .and_then(|units| i32::try_from(units).ok())
            .filter(|units| *units > 0);
        let customer_id = billing_id_value(&data, "customer");
        let updated = state
            .database
            .client
            .execute(
                r#"
                  UPDATE workspace_billing
                  SET status = COALESCE($1, status),
                      current_period_end = $2::text::timestamp,
                      canceled_at = $3::text::timestamp,
                      creem_product_id = COALESCE($4, creem_product_id),
                      plan = CASE WHEN $4 IS NULL THEN plan ELSE $5 END,
                      billing_interval = CASE WHEN $4 IS NULL THEN billing_interval ELSE $6 END,
                      seats = COALESCE($7, seats),
                      creem_customer_id = COALESCE($8, creem_customer_id),
                      updated_at = NOW()
                  WHERE creem_subscription_id = $9
                "#,
                &[
                    &status,
                    &current_period_end,
                    &canceled_at,
                    &product_id,
                    &plan,
                    &interval,
                    &seats,
                    &customer_id,
                    &subscription_id,
                ],
            )
            .await
            .map_err(database_error)?;
        if updated == 0 {
            let workspace_id = billing_metadata_value(&data, "workspaceId");
            if let Some(workspace_id) = workspace_id {
                state
                    .database
                    .client
                    .execute(
                        r#"
                          UPDATE workspace_billing
                          SET creem_subscription_id = $9,
                              status = COALESCE($1, status),
                              current_period_end = $2::text::timestamp,
                              canceled_at = $3::text::timestamp,
                              creem_product_id = COALESCE($4, creem_product_id),
                              plan = CASE WHEN $4 IS NULL THEN plan ELSE $5 END,
                              billing_interval = CASE WHEN $4 IS NULL THEN billing_interval ELSE $6 END,
                              seats = COALESCE($7, seats),
                              creem_customer_id = COALESCE($8, creem_customer_id),
                              updated_at = NOW()
                          WHERE workspace_id = $10
                        "#,
                        &[
                            &status,
                            &current_period_end,
                            &canceled_at,
                            &product_id,
                            &plan,
                            &interval,
                            &seats,
                            &customer_id,
                            &subscription_id,
                            &workspace_id,
                        ],
                    )
                    .await
                    .map_err(database_error)?;
            }
        }
    }

    Ok(Json(json!({ "processed": true, "duplicate": false })))
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn append_orchestrator_message(record: &mut OrchestratorRecord, role: &str, text: &str) {
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    let text = text.chars().take(20_000).collect::<String>();
    if record
        .messages
        .last()
        .is_some_and(|message| message.role == role && message.text == text)
    {
        return;
    }
    record.messages.push(OrchestratorMessage {
        id: Uuid::new_v4().to_string(),
        role: role.to_string(),
        text,
        at: now_rfc3339(),
    });
    if record.messages.len() > 200 {
        let remove = record.messages.len() - 200;
        record.messages.drain(0..remove);
    }
}

fn refresh_orchestrator_status(
    record: &mut OrchestratorRecord,
    runner: &RunManager,
    nested_statuses: &HashMap<String, OrchestratorStatus>,
) {
    if record.cancel_requested {
        record.status = OrchestratorStatus::Cancelled;
        return;
    }

    let parent_active = record
        .active_turn_id
        .as_deref()
        .and_then(|id| runner.get(id))
        .is_some_and(|run| run.status.is_active());
    let mut child_active = false;
    let mut child_failed = false;
    for child in &mut record.children {
        if let Some(run) = runner.get(&child.run_id) {
            child.status = run.status;
            child.error = run.error.clone();
            if run.status.is_active() {
                child_active = true;
            }
            if run.status == RunStatus::Failed {
                child_failed = true;
            }
        } else if child.status.is_active() {
            child_active = true;
        }
        if let Some(status) = child
            .orchestrator_id
            .as_ref()
            .and_then(|id| nested_statuses.get(id))
        {
            match status {
                OrchestratorStatus::Queued | OrchestratorStatus::Running => {
                    child_active = true;
                }
                OrchestratorStatus::Failed | OrchestratorStatus::Cancelled => {
                    child_failed = true;
                }
                OrchestratorStatus::Waiting => {}
            }
        }
    }

    if parent_active || child_active {
        record.status = OrchestratorStatus::Running;
    } else if child_failed || record.error.is_some() {
        record.status = OrchestratorStatus::Failed;
    } else {
        record.status = OrchestratorStatus::Waiting;
    }
}

fn refresh_orchestrator_tree(
    records: &mut HashMap<String, OrchestratorRecord>,
    orchestrator_id: &str,
    runner: &RunManager,
) {
    fn visit(
        records: &mut HashMap<String, OrchestratorRecord>,
        orchestrator_id: &str,
        runner: &RunManager,
        visiting: &mut HashSet<String>,
    ) {
        if !visiting.insert(orchestrator_id.to_string()) {
            return;
        }
        let nested_ids = records
            .get(orchestrator_id)
            .map(|record| {
                record
                    .children
                    .iter()
                    .filter_map(|child| child.orchestrator_id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for nested_id in &nested_ids {
            visit(records, nested_id, runner, visiting);
        }
        let nested_statuses = nested_ids
            .iter()
            .filter_map(|id| records.get(id).map(|record| (id.clone(), record.status)))
            .collect::<HashMap<_, _>>();
        if let Some(record) = records.get_mut(orchestrator_id) {
            refresh_orchestrator_status(record, runner, &nested_statuses);
        }
        visiting.remove(orchestrator_id);
    }

    visit(records, orchestrator_id, runner, &mut HashSet::new());
}

fn orchestrator_response(
    record: &OrchestratorRecord,
    runner: &RunManager,
    records: &HashMap<String, OrchestratorRecord>,
) -> OrchestratorResponse {
    fn at_depth(
        record: &OrchestratorRecord,
        runner: &RunManager,
        records: &HashMap<String, OrchestratorRecord>,
        depth: usize,
    ) -> OrchestratorResponse {
        OrchestratorResponse {
            id: record.id.clone(),
            parent_orchestrator_id: record.parent_orchestrator_id.clone(),
            parent_child_id: record.parent_child_id.clone(),
            depth: record.depth,
            workspace_id: record.workspace_id.clone(),
            project_id: record.project_id.clone(),
            goal: record.goal.clone(),
            cwd: record.cwd.display().to_string(),
            model: record.model.clone(),
            network_access: record.network_access,
            max_children: record.max_children,
            max_retries: record.max_retries,
            max_seconds: record.max_seconds,
            status: record.status,
            created_at: record.created_at.clone(),
            updated_at: record.updated_at.clone(),
            active_turn_id: record.active_turn_id.clone(),
            error: record.error.clone(),
            messages: record.messages.clone(),
            children: record
                .children
                .iter()
                .map(|child| {
                    let run = runner.get(&child.run_id);
                    let orchestrator = if depth < MAX_ORCHESTRATOR_RESPONSE_DEPTH {
                        child
                            .orchestrator_id
                            .as_ref()
                            .and_then(|id| records.get(id))
                            .map(|nested| Box::new(at_depth(nested, runner, records, depth + 1)))
                    } else {
                        None
                    };
                    OrchestratorChildResponse {
                        id: child.id.clone(),
                        orchestrator_id: child.orchestrator_id.clone(),
                        task_id: child.task_id.clone(),
                        prompt: child.prompt.clone(),
                        cwd: child.cwd.display().to_string(),
                        model: child.model.clone(),
                        network_access: child.network_access,
                        max_seconds: child.max_seconds,
                        attempt: child.attempt,
                        max_retries: child.max_retries,
                        run_id: child.run_id.clone(),
                        status: run.as_ref().map_or(child.status, |run| run.status),
                        error: run
                            .as_ref()
                            .and_then(|run| run.error.clone())
                            .or_else(|| child.error.clone()),
                        created_at: child.created_at.clone(),
                        updated_at: child.updated_at.clone(),
                        run: run.map(agent_response),
                        orchestrator,
                    }
                })
                .collect(),
        }
    }

    at_depth(record, runner, records, 0)
}

async fn orchestrator_snapshot(
    state: &AppState,
    orchestrator_id: &str,
) -> Result<OrchestratorResponse, ApiError> {
    let mut orchestrators = state.orchestrators.lock().await;
    if !orchestrators.records.contains_key(orchestrator_id) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Orchestrator not found",
        ));
    }
    refresh_orchestrator_tree(
        &mut orchestrators.records,
        orchestrator_id,
        &state.orchestrator_runner,
    );
    if let Some(record) = orchestrators.records.get_mut(orchestrator_id) {
        record.updated_at = now_rfc3339();
    }
    let snapshot = orchestrators
        .records
        .get(orchestrator_id)
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Orchestrator not found"))?;
    let records = orchestrators.records.clone();
    Ok(orchestrator_response(
        &snapshot,
        &state.orchestrator_runner,
        &records,
    ))
}

fn publish_orchestrator_event(
    state: &AppState,
    event_type: &str,
    record: &OrchestratorRecord,
    agent_run_id: Option<String>,
    text: Option<String>,
) {
    let _ = state.events.send(SocketEvent {
        event_type: event_type.to_string(),
        project_id: Some(record.project_id.clone()),
        orchestrator_id: Some(record.id.clone()),
        agent_run_id,
        text,
        status: Some(record.status),
        ..Default::default()
    });
}

fn agent_final_text(run: &AgentRun) -> Option<String> {
    run.events
        .iter()
        .rev()
        .filter(|event| {
            !event.text.trim().is_empty()
                && !matches!(
                    event.event_type.as_str(),
                    "run.started" | "run.completed" | "run.failed" | "run.cancelled" | "timeout"
                )
        })
        .map(|event| event.text.trim().to_string())
        .find(|text| !text.is_empty())
        .or_else(|| run.error.clone())
}

fn build_codex_command_args(
    cwd: &FsPath,
    model: Option<&str>,
    network_access: bool,
    prompt: &str,
) -> Vec<String> {
    let api_url = env::var("KANEO_API_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:1337".to_string())
        .trim_end_matches('/')
        .to_string();
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
        format!("mcp_servers.kaneo.url=\"{api_url}/api/mcp\""),
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
    if let Some(model) = model.map(str::trim).filter(|model| !model.is_empty()) {
        command_args.extend(["--model".to_string(), model.to_string()]);
    }
    command_args.push(prompt.to_string());
    command_args
}

fn resolve_orchestrator_cwd(
    cwd: Option<&str>,
    project_cwd: Option<&str>,
    orchestrator_id: &str,
) -> Result<PathBuf, ApiError> {
    let requested_cwd = cwd
        .map(str::trim)
        .filter(|cwd| !cwd.is_empty())
        .or_else(|| project_cwd.map(str::trim).filter(|cwd| !cwd.is_empty()));
    let path = if let Some(cwd) = requested_cwd {
        let path = PathBuf::from(cwd);
        if !path.is_absolute() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "The orchestrator working directory must be an absolute path.",
            ));
        }
        path
    } else {
        PathBuf::from(env::temp_dir())
            .join("kaneo-orchestrators")
            .join(orchestrator_id)
    };
    if let Some(root) = env::var_os("KANEO_AGENT_ALLOWED_ROOT") {
        let root = FsPath::new(&root);
        if !path.starts_with(root) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("Agent working directory must be inside {}.", root.display()),
            ));
        }
    }
    Ok(path)
}

fn build_orchestrator_prompt(record: &OrchestratorRecord) -> String {
    let history = record
        .messages
        .iter()
        .map(|message| format!("[{}] {}", message.role, message.text))
        .collect::<Vec<_>>()
        .join("\n");
    let children = if record.children.is_empty() {
        "No child agents have been delegated yet.".to_string()
    } else {
        record
            .children
            .iter()
            .map(|child| {
                format!(
                    "- child {} task={} attempt={}/{} run={} status={:?}",
                    child.id,
                    child.task_id.as_deref().unwrap_or("none"),
                    child.attempt,
                    child.max_retries + 1,
                    child.run_id,
                    child.status
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    [
        "You are the Kaneo orchestrator agent for a Kanban project.",
        &format!("Orchestrator ID: {}", record.id),
        &format!("Workspace ID: {}", record.workspace_id),
        &format!("Project ID: {}", record.project_id),
        &format!(
            "Delegate at most {} child agents; each child may be retried up to {} time(s).",
            record.max_children, record.max_retries
        ),
        "Use the configured Kaneo MCP server as the source of truth.",
        "Start by calling whoami, get_project, and list_tasks for this project.",
        "Decompose the goal into independent, concrete Kanban tasks. Create missing tasks when useful, then call orchestrator_delegate once per independent task.",
        "Pass the exact taskId to orchestrator_delegate when a child owns an existing task. Never delegate destructive work and never claim completion without checking child results.",
        "Use orchestrator_children to monitor delegated work. Keep task statuses and comments current through Kaneo MCP.",
        "You coordinate; child agents do the implementation. Do not edit the project directly unless a small coordination-only change is unavoidable.",
        "When all useful work is complete, summarize child results, checks, and remaining blockers in your final response.",
        "",
        "Current child agents:",
        &children,
        "",
        "Conversation:",
        &history,
    ]
    .join("\n")
}

fn build_orchestrator_child_prompt(
    record: &OrchestratorRecord,
    child_orchestrator_id: &str,
    task_id: Option<&str>,
    prompt: &str,
) -> String {
    let task_context = task_id
        .map(|task_id| format!("Kaneo task ID: {task_id}"))
        .unwrap_or_else(|| {
            "No existing task ID was supplied; report useful work back to the orchestrator."
                .to_string()
        });
    [
        "You are a child delivery agent coordinated by a Kaneo orchestrator.",
        &format!("Parent orchestrator ID: {}", record.id),
        &format!("Your child orchestrator ID: {child_orchestrator_id}"),
        &format!("Kaneo workspace ID: {}", record.workspace_id),
        &format!("Kaneo project ID: {}", record.project_id),
        &task_context,
        "Use the configured Kaneo MCP server and the supplied working directory.",
        "You are an orchestrator for your own context. If you need parallel work, call orchestrator_delegate with your child orchestrator ID above; those agents will appear beneath you in the execution tree.",
        "Inspect the task and repository before acting. Keep the task status and comments accurate as you work.",
        "Do not delete projects, tasks, comments, labels, or relations. Run focused checks and report evidence, blockers, and changed files in your final response.",
        "",
        "Assigned child goal:",
        prompt.trim(),
    ]
    .join("\n")
}

fn build_orchestrator_spec(
    record: &OrchestratorRecord,
    run_id: String,
    prompt: String,
    cwd: PathBuf,
    model: Option<String>,
    network_access: bool,
    max_seconds: u64,
    execution_orchestrator_id: &str,
    parent_orchestrator_id: Option<&str>,
    child_id: Option<&str>,
    task_id: Option<&str>,
) -> AgentSpec {
    let api_url = env::var("KANEO_API_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:1337".to_string())
        .trim_end_matches('/')
        .to_string();
    let mut environment = std::collections::BTreeMap::new();
    environment.insert("KANEO_AGENT_TOKEN".to_string(), record.credential.clone());
    environment.insert("CODEX_CI".to_string(), "1".to_string());
    environment.insert("KANEO_API_URL".to_string(), api_url);
    environment.insert(
        "KANEO_WORKSPACE_ID".to_string(),
        record.workspace_id.clone(),
    );
    environment.insert("KANEO_PROJECT_ID".to_string(), record.project_id.clone());
    environment.insert(
        "KANEO_ORCHESTRATOR_ID".to_string(),
        execution_orchestrator_id.to_string(),
    );
    let execution_depth = record.depth
        + if parent_orchestrator_id.is_some() {
            1
        } else {
            0
        };
    environment.insert(
        "KANEO_ORCHESTRATOR_DEPTH".to_string(),
        execution_depth.to_string(),
    );
    if let Some(parent_orchestrator_id) = parent_orchestrator_id {
        environment.insert(
            "KANEO_PARENT_ORCHESTRATOR_ID".to_string(),
            parent_orchestrator_id.to_string(),
        );
    }
    if let Some(child_id) = child_id {
        environment.insert("KANEO_CHILD_ID".to_string(), child_id.to_string());
    }
    if let Some(task_id) = task_id {
        environment.insert("KANEO_TASK_ID".to_string(), task_id.to_string());
    }
    AgentSpec {
        id: Some(run_id),
        workspace_id: record.workspace_id.clone(),
        project_id: record.project_id.clone(),
        prompt: prompt.clone(),
        cwd: cwd.clone(),
        model: model.clone(),
        network_access,
        command: env::var("KANEO_CODEX_BIN").unwrap_or_else(|_| "codex".to_string()),
        command_args: build_codex_command_args(&cwd, model.as_deref(), network_access, &prompt),
        environment,
        max_seconds,
    }
}

async fn start_orchestrator_turn(
    state: &AppState,
    auth: &AuthContext,
    orchestrator_id: &str,
) -> Result<AgentRun, ApiError> {
    let record = {
        let mut orchestrators = state.orchestrators.lock().await;
        if !orchestrators.records.contains_key(orchestrator_id) {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "Orchestrator not found",
            ));
        }
        refresh_orchestrator_tree(
            &mut orchestrators.records,
            orchestrator_id,
            &state.orchestrator_runner,
        );
        let record = orchestrators
            .records
            .get_mut(orchestrator_id)
            .expect("orchestrator existence checked above");
        if record.cancel_requested {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "Orchestrator has been cancelled",
            ));
        }
        if record
            .active_turn_id
            .as_deref()
            .and_then(|id| state.orchestrator_runner.get(id))
            .is_some_and(|run| run.status.is_active())
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "Orchestrator already has an active turn",
            ));
        }
        record.error = None;
        record.status = OrchestratorStatus::Queued;
        record.clone()
    };
    if !record.cwd.is_dir() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "Orchestrator working directory is not a directory: {}",
                record.cwd.display()
            ),
        ));
    }
    let run_id = Uuid::new_v4().to_string();
    let prompt = build_orchestrator_prompt(&record);
    let spec = build_orchestrator_spec(
        &OrchestratorRecord {
            credential: auth.credential.clone(),
            ..record.clone()
        },
        run_id,
        prompt,
        record.cwd.clone(),
        record.model.clone(),
        record.network_access,
        record.max_seconds,
        &record.id,
        None,
        None,
        None,
    );
    let run = match state.orchestrator_runner.start(spec) {
        Ok(run) => run,
        Err(error) => {
            let mut orchestrators = state.orchestrators.lock().await;
            if let Some(record) = orchestrators.records.get_mut(orchestrator_id) {
                record.status = OrchestratorStatus::Failed;
                record.error = Some(error.to_string());
                record.updated_at = now_rfc3339();
            }
            return Err(ApiError::new(StatusCode::CONFLICT, error.to_string()));
        }
    };
    let accepted = {
        let mut orchestrators = state.orchestrators.lock().await;
        let record = orchestrators
            .records
            .get_mut(orchestrator_id)
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Orchestrator not found"))?;
        if record.cancel_requested
            || record
                .active_turn_id
                .as_deref()
                .and_then(|id| state.orchestrator_runner.get(id))
                .is_some_and(|active| active.status.is_active())
        {
            false
        } else {
            record.active_turn_id = Some(run.id.clone());
            record.status = OrchestratorStatus::Running;
            record.updated_at = now_rfc3339();
            true
        }
    };
    if !accepted {
        let _ = state.orchestrator_runner.cancel(&run.id);
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Orchestrator already has an active turn or was cancelled",
        ));
    }
    let record = {
        let orchestrators = state.orchestrators.lock().await;
        orchestrators.records.get(orchestrator_id).cloned()
    };
    if let Some(record) = record {
        publish_orchestrator_event(
            state,
            "ORCHESTRATOR_TURN_STARTED",
            &record,
            Some(run.id.clone()),
            Some("Orchestrator turn started.".to_string()),
        );
    }
    spawn_orchestrator_parent_watcher(state.clone(), orchestrator_id.to_string(), run.id.clone());
    Ok(run)
}

fn spawn_orchestrator_parent_watcher(state: AppState, orchestrator_id: String, run_id: String) {
    tokio::spawn(async move {
        loop {
            let Some(run) = state.orchestrator_runner.get(&run_id) else {
                return;
            };
            if run.status.is_active() {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            let final_text = agent_final_text(&run);
            let event_record = {
                let mut orchestrators = state.orchestrators.lock().await;
                if let Some(record) = orchestrators.records.get_mut(&orchestrator_id) {
                    if record.active_turn_id.as_deref() == Some(run_id.as_str()) {
                        record.active_turn_id = None;
                    }
                    if !record.cancel_requested && run.status == RunStatus::Completed {
                        if let Some(text) = final_text.as_deref() {
                            append_orchestrator_message(record, "assistant", text);
                        }
                    }
                    if run.status == RunStatus::Failed {
                        record.error = run.error.clone().or_else(|| final_text.clone());
                    } else if run.status == RunStatus::Cancelled && !record.cancel_requested {
                        record.error = Some("Orchestrator turn was cancelled.".to_string());
                    }
                    record.updated_at = now_rfc3339();
                }
                refresh_orchestrator_tree(
                    &mut orchestrators.records,
                    &orchestrator_id,
                    &state.orchestrator_runner,
                );
                orchestrators.records.get(&orchestrator_id).cloned()
            };
            if let Some(record) = event_record {
                publish_orchestrator_event(
                    &state,
                    "ORCHESTRATOR_TURN_FINISHED",
                    &record,
                    Some(run_id.clone()),
                    final_text,
                );
            }
            return;
        }
    });
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

fn resolve_agent_cwd(
    input: &StartAgentInput,
    project_cwd: Option<&str>,
    run_id: &str,
) -> Result<PathBuf, ApiError> {
    let requested_cwd = input
        .cwd
        .as_deref()
        .map(str::trim)
        .filter(|cwd| !cwd.is_empty())
        .or_else(|| project_cwd.map(str::trim).filter(|cwd| !cwd.is_empty()));
    let cwd = if let Some(cwd) = requested_cwd {
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
    if input.prompt.chars().count() > 20_000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "prompt must be 20000 characters or fewer",
        ));
    }
    if input
        .cwd
        .as_deref()
        .is_some_and(|cwd| cwd.chars().count() > 1_000)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cwd must be 1000 characters or fewer",
        ));
    }
    if input.max_seconds.is_some_and(|seconds| seconds < 60) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "maxSeconds must be at least 60",
        ));
    }
    let (auth, workspace_id) = auth_for_project(&state, &headers, &input.project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "project", "read").await?;
    require_workspace_permission(&state, &auth, &workspace_id, "task", "create").await?;
    require_workspace_permission(&state, &auth, &workspace_id, "task", "update").await?;
    let id = Uuid::new_v4().to_string();
    let project_cwd = project_local_path(&state.database, &input.project_id).await?;
    let cwd = resolve_agent_cwd(&input, project_cwd.as_deref(), &id)?;
    if !cwd.is_dir() {
        if input
            .cwd
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || project_cwd.is_some()
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
    let kaneo_api_url = env::var("KANEO_API_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:1337".to_string())
        .trim_end_matches('/')
        .to_string();
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
        format!("mcp_servers.kaneo.url=\"{kaneo_api_url}/api/mcp\""),
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
    environment.insert("KANEO_API_URL".to_string(), kaneo_api_url);
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

async fn delegate_orchestrator_child(
    state: &AppState,
    auth: &AuthContext,
    args: &Value,
) -> Result<Value, String> {
    let orchestrator_id = mcp_required_string(args, "orchestratorId")?;
    let prompt = mcp_required_text(args, "prompt")?;
    if prompt.trim().is_empty() {
        return Err("prompt must not be empty".to_string());
    }
    if prompt.chars().count() > 20_000 {
        return Err("prompt must be 20000 characters or fewer".to_string());
    }
    let task_id = mcp_optional_string(args, "taskId")?;
    let cwd = mcp_optional_string(args, "cwd")?;
    if cwd
        .as_deref()
        .is_some_and(|cwd| cwd.chars().count() > 1_000)
    {
        return Err("cwd must be 1000 characters or fewer".to_string());
    }
    let model = mcp_optional_string(args, "model")?;
    let network_access = mcp_optional_bool(args, "networkAccess")?.unwrap_or(false);
    let max_seconds = mcp_optional_positive_i64(args, "maxSeconds")?
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| "maxSeconds is outside the supported range".to_string())
        })
        .transpose()?;

    let record = {
        let mut orchestrators = state.orchestrators.lock().await;
        refresh_orchestrator_tree(
            &mut orchestrators.records,
            &orchestrator_id,
            &state.orchestrator_runner,
        );
        orchestrators
            .records
            .get(&orchestrator_id)
            .cloned()
            .ok_or_else(|| "Orchestrator not found".to_string())?
    };
    require_workspace(state, auth, &record.workspace_id)
        .await
        .map_err(|error| error.message.clone())?;
    require_workspace_permission(state, auth, &record.workspace_id, "project", "read")
        .await
        .map_err(|error| error.message.clone())?;
    require_workspace_permission(state, auth, &record.workspace_id, "task", "update")
        .await
        .map_err(|error| error.message.clone())?;
    if record.cancel_requested {
        return Err("Orchestrator has been cancelled".to_string());
    }
    if record.depth >= MAX_ORCHESTRATOR_DEPTH {
        return Err(format!(
            "Orchestrator nesting is limited to {MAX_ORCHESTRATOR_DEPTH} levels"
        ));
    }
    if record.children.len() >= record.max_children {
        return Err(format!(
            "Orchestrator already has its maximum of {} child agents",
            record.max_children
        ));
    }
    if let Some(task_id) = task_id.as_deref() {
        let task = mcp_api_request(
            state,
            auth,
            reqwest::Method::GET,
            &format!("/api/task/{}", mcp_path_segment(task_id)),
            None,
        )
        .await?;
        if task.get("projectId").and_then(Value::as_str) != Some(record.project_id.as_str()) {
            return Err("taskId must belong to the orchestrator project".to_string());
        }
    }

    let child_id = Uuid::new_v4().to_string();
    let child_orchestrator_id = Uuid::new_v4().to_string();
    let run_id = Uuid::new_v4().to_string();
    let child_cwd = if let Some(cwd) = cwd.as_deref() {
        let child_cwd = PathBuf::from(cwd);
        if !child_cwd.is_absolute() {
            return Err("The child working directory must be an absolute path".to_string());
        }
        child_cwd
    } else {
        record.cwd.clone()
    };
    if !child_cwd.is_dir() {
        return Err(format!(
            "Child working directory is not a directory: {}",
            child_cwd.display()
        ));
    }
    if let Some(root) = env::var_os("KANEO_AGENT_ALLOWED_ROOT") {
        let root = FsPath::new(&root);
        if !child_cwd.starts_with(root) {
            return Err(format!(
                "Child working directory must be inside {}",
                root.display()
            ));
        }
    }
    let child_prompt = build_orchestrator_child_prompt(
        &record,
        &child_orchestrator_id,
        task_id.as_deref(),
        &prompt,
    );
    let child_model = model.or_else(|| record.model.clone());
    let child_max_seconds = max_seconds.unwrap_or(record.max_seconds);
    if child_max_seconds < 60 {
        return Err("maxSeconds must be at least 60".to_string());
    }
    let spec = build_orchestrator_spec(
        &record,
        run_id.clone(),
        child_prompt.clone(),
        child_cwd.clone(),
        child_model.clone(),
        network_access || record.network_access,
        child_max_seconds,
        &child_orchestrator_id,
        Some(&record.id),
        Some(&child_id),
        task_id.as_deref(),
    );
    let run = state
        .orchestrator_runner
        .start(spec)
        .map_err(|error| error.to_string())?;
    let child = OrchestratorChild {
        id: child_id.clone(),
        orchestrator_id: Some(child_orchestrator_id.clone()),
        task_id: task_id.clone(),
        prompt,
        cwd: child_cwd,
        model: child_model,
        network_access: network_access || record.network_access,
        max_seconds: child_max_seconds,
        attempt: 1,
        max_retries: record.max_retries,
        run_id: run.id.clone(),
        status: run.status,
        error: None,
        created_at: now_rfc3339(),
        updated_at: now_rfc3339(),
    };
    let child_record = OrchestratorRecord {
        id: child_orchestrator_id.clone(),
        parent_orchestrator_id: Some(record.id.clone()),
        parent_child_id: Some(child_id.clone()),
        depth: record.depth + 1,
        workspace_id: record.workspace_id.clone(),
        project_id: record.project_id.clone(),
        credential: auth.credential.clone(),
        goal: child.prompt.clone(),
        cwd: child.cwd.clone(),
        model: child.model.clone(),
        network_access: child.network_access,
        max_children: record.max_children,
        max_retries: record.max_retries,
        max_seconds: child.max_seconds,
        status: OrchestratorStatus::Running,
        created_at: child.created_at.clone(),
        updated_at: child.updated_at.clone(),
        active_turn_id: Some(run.id.clone()),
        error: None,
        cancel_requested: false,
        messages: vec![OrchestratorMessage {
            id: Uuid::new_v4().to_string(),
            role: "user".to_string(),
            text: child.prompt.clone(),
            at: now_rfc3339(),
        }],
        children: Vec::new(),
    };
    let event_record = {
        let mut orchestrators = state.orchestrators.lock().await;
        let accepted = orchestrators
            .records
            .get(&orchestrator_id)
            .is_some_and(|record| {
                !record.cancel_requested && record.children.len() < record.max_children
            });
        if !accepted {
            None
        } else {
            orchestrators
                .records
                .insert(child_orchestrator_id.clone(), child_record);
            let record = orchestrators
                .records
                .get_mut(&orchestrator_id)
                .expect("parent orchestrator existence checked above");
            record.children.push(child);
            record.status = OrchestratorStatus::Running;
            record.updated_at = now_rfc3339();
            Some(record.clone())
        }
    };
    let Some(event_record) = event_record else {
        let _ = state.orchestrator_runner.cancel(&run.id);
        return Err("Orchestrator was cancelled or reached its child limit".to_string());
    };
    publish_orchestrator_event(
        state,
        "ORCHESTRATOR_CHILD_STARTED",
        &event_record,
        Some(run.id.clone()),
        Some(format!("Child agent {child_id} started.")),
    );
    spawn_orchestrator_child_watcher(
        state.clone(),
        orchestrator_id,
        child_id.clone(),
        run.id.clone(),
    );
    Ok(json!({
        "orchestratorId": event_record.id,
        "childOrchestratorId": child_orchestrator_id,
        "childId": child_id,
        "runId": run.id,
        "taskId": task_id,
        "status": run.status,
    }))
}

async fn orchestrator_children_value(
    state: &AppState,
    auth: &AuthContext,
    orchestrator_id: &str,
) -> Result<Value, String> {
    let record = {
        let orchestrators = state.orchestrators.lock().await;
        orchestrators
            .records
            .get(orchestrator_id)
            .cloned()
            .ok_or_else(|| "Orchestrator not found".to_string())?
    };
    require_workspace(state, auth, &record.workspace_id)
        .await
        .map_err(|error| error.message.clone())?;
    serde_json::to_value(
        orchestrator_snapshot(state, orchestrator_id)
            .await
            .map_err(|error| error.message)?,
    )
    .map_err(|error| format!("Could not serialize orchestrator state: {error}"))
}

fn finish_nested_orchestrator_run(
    records: &mut HashMap<String, OrchestratorRecord>,
    child_orchestrator_id: Option<&str>,
    run: &AgentRun,
    final_text: Option<&str>,
) {
    let Some(child_orchestrator_id) = child_orchestrator_id else {
        return;
    };
    let Some(record) = records.get_mut(child_orchestrator_id) else {
        return;
    };
    if record.active_turn_id.as_deref() == Some(run.id.as_str()) {
        record.active_turn_id = None;
    }
    if !record.cancel_requested && run.status == RunStatus::Completed {
        if let Some(text) = final_text {
            append_orchestrator_message(record, "assistant", text);
        }
    }
    if run.status == RunStatus::Failed {
        record.error = run.error.clone().or_else(|| final_text.map(str::to_string));
    } else if run.status == RunStatus::Cancelled && !record.cancel_requested {
        record.error = Some("Child orchestrator turn was cancelled.".to_string());
    }
    record.updated_at = now_rfc3339();
}

fn cancel_orchestrator_tree(
    records: &mut HashMap<String, OrchestratorRecord>,
    orchestrator_id: &str,
    run_ids: &mut HashSet<String>,
    visiting: &mut HashSet<String>,
) {
    if !visiting.insert(orchestrator_id.to_string()) {
        return;
    }
    let (active_turn_id, children) = records
        .get(orchestrator_id)
        .map(|record| {
            (
                record.active_turn_id.clone(),
                record
                    .children
                    .iter()
                    .map(|child| (child.run_id.clone(), child.orchestrator_id.clone()))
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap_or_default();
    if let Some(record) = records.get_mut(orchestrator_id) {
        record.cancel_requested = true;
        record.status = OrchestratorStatus::Cancelled;
        record.updated_at = now_rfc3339();
    }
    if let Some(run_id) = active_turn_id {
        run_ids.insert(run_id);
    }
    for (run_id, child_orchestrator_id) in children {
        run_ids.insert(run_id);
        if let Some(child_orchestrator_id) = child_orchestrator_id {
            cancel_orchestrator_tree(records, &child_orchestrator_id, run_ids, visiting);
        }
    }
    visiting.remove(orchestrator_id);
}

fn spawn_orchestrator_child_watcher(
    state: AppState,
    orchestrator_id: String,
    child_id: String,
    run_id: String,
) {
    tokio::spawn(async move {
        loop {
            let Some(run) = state.orchestrator_runner.get(&run_id) else {
                return;
            };
            if run.status.is_active() {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }

            let final_text = agent_final_text(&run);
            let mut retry_context: Option<(OrchestratorRecord, OrchestratorChild)> = None;
            let event_record = {
                let mut orchestrators = state.orchestrators.lock().await;
                let child_orchestrator_id =
                    orchestrators
                        .records
                        .get(&orchestrator_id)
                        .and_then(|record| {
                            record
                                .children
                                .iter()
                                .find(|child| child.id == child_id && child.run_id == run_id)
                                .and_then(|child| child.orchestrator_id.clone())
                        });
                finish_nested_orchestrator_run(
                    &mut orchestrators.records,
                    child_orchestrator_id.as_deref(),
                    &run,
                    final_text.as_deref(),
                );
                if let Some(record) = orchestrators.records.get_mut(&orchestrator_id) {
                    let retry_record = record.clone();
                    if let Some(child) = record
                        .children
                        .iter_mut()
                        .find(|child| child.id == child_id && child.run_id == run_id)
                    {
                        child.status = run.status;
                        child.error = run.error.clone();
                        child.updated_at = now_rfc3339();
                        if run.status == RunStatus::Failed
                            && !record.cancel_requested
                            && child.attempt <= child.max_retries
                        {
                            retry_context = Some((retry_record, child.clone()));
                            record.error = None;
                        } else if run.status == RunStatus::Failed {
                            record.error = run
                                .error
                                .clone()
                                .or_else(|| Some(format!("Child agent {child_id} failed.")));
                        }
                        record.updated_at = now_rfc3339();
                    }
                }
                refresh_orchestrator_tree(
                    &mut orchestrators.records,
                    &orchestrator_id,
                    &state.orchestrator_runner,
                );
                orchestrators.records.get(&orchestrator_id).cloned()
            };

            if let Some((record, child)) = retry_context {
                let next_attempt = child.attempt + 1;
                let next_run_id = Uuid::new_v4().to_string();
                let child_orchestrator_id = child
                    .orchestrator_id
                    .clone()
                    .unwrap_or_else(|| record.id.clone());
                let spec = build_orchestrator_spec(
                    &record,
                    next_run_id,
                    build_orchestrator_child_prompt(
                        &record,
                        &child_orchestrator_id,
                        child.task_id.as_deref(),
                        &child.prompt,
                    ),
                    child.cwd.clone(),
                    child.model.clone(),
                    child.network_access,
                    child.max_seconds,
                    &child_orchestrator_id,
                    Some(&record.id),
                    Some(&child.id),
                    child.task_id.as_deref(),
                );
                match state.orchestrator_runner.start(spec) {
                    Ok(next_run) => {
                        let mut accepted = false;
                        let mut retry_record = None;
                        {
                            let mut orchestrators = state.orchestrators.lock().await;
                            let mut accepted_child_orchestrator_id = None;
                            if let Some(record) = orchestrators.records.get_mut(&orchestrator_id) {
                                if let Some(current) = record.children.iter_mut().find(|current| {
                                    current.id == child_id && current.run_id == run_id
                                }) {
                                    if !record.cancel_requested {
                                        accepted_child_orchestrator_id =
                                            current.orchestrator_id.clone();
                                        current.attempt = next_attempt;
                                        current.run_id = next_run.id.clone();
                                        current.status = next_run.status;
                                        current.error = None;
                                        current.updated_at = now_rfc3339();
                                        record.error = None;
                                        record.status = OrchestratorStatus::Running;
                                        record.updated_at = now_rfc3339();
                                        retry_record = Some(record.clone());
                                        accepted = true;
                                    }
                                }
                            }
                            if let Some(child_orchestrator_id) = accepted_child_orchestrator_id {
                                if let Some(child_record) =
                                    orchestrators.records.get_mut(&child_orchestrator_id)
                                {
                                    child_record.active_turn_id = Some(next_run.id.clone());
                                    child_record.status = OrchestratorStatus::Running;
                                    child_record.error = None;
                                    child_record.updated_at = now_rfc3339();
                                }
                            }
                            refresh_orchestrator_tree(
                                &mut orchestrators.records,
                                &orchestrator_id,
                                &state.orchestrator_runner,
                            );
                            if accepted {
                                retry_record = orchestrators.records.get(&orchestrator_id).cloned();
                            }
                        }
                        if accepted {
                            if let Some(record) = retry_record {
                                publish_orchestrator_event(
                                    &state,
                                    "ORCHESTRATOR_CHILD_RETRYING",
                                    &record,
                                    Some(next_run.id.clone()),
                                    Some(format!(
                                        "Child agent {child_id} failed; retry {next_attempt}/{} started.",
                                        child.max_retries + 1
                                    )),
                                );
                            }
                            spawn_orchestrator_child_watcher(
                                state.clone(),
                                orchestrator_id.clone(),
                                child_id.clone(),
                                next_run.id,
                            );
                            return;
                        }
                        let _ = state.orchestrator_runner.cancel(&next_run.id);
                    }
                    Err(error) => {
                        let error = error.to_string();
                        let failure_record = {
                            let mut orchestrators = state.orchestrators.lock().await;
                            if let Some(record) = orchestrators.records.get_mut(&orchestrator_id) {
                                if let Some(current) = record.children.iter_mut().find(|current| {
                                    current.id == child_id && current.run_id == run_id
                                }) {
                                    current.error = Some(error.clone());
                                    current.status = RunStatus::Failed;
                                    current.updated_at = now_rfc3339();
                                    record.error = Some(error);
                                    record.updated_at = now_rfc3339();
                                }
                            }
                            refresh_orchestrator_tree(
                                &mut orchestrators.records,
                                &orchestrator_id,
                                &state.orchestrator_runner,
                            );
                            orchestrators.records.get(&orchestrator_id).cloned()
                        };
                        if let Some(record) = failure_record {
                            publish_orchestrator_event(
                                &state,
                                "ORCHESTRATOR_CHILD_FINISHED",
                                &record,
                                Some(run_id.clone()),
                                Some(format!("Child agent {child_id} could not be retried.")),
                            );
                        }
                        return;
                    }
                }
            }

            if let Some(record) = event_record {
                publish_orchestrator_event(
                    &state,
                    "ORCHESTRATOR_CHILD_FINISHED",
                    &record,
                    Some(run_id),
                    final_text,
                );
            }
            return;
        }
    });
}

async fn create_orchestrator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateOrchestratorInput>,
) -> Result<(StatusCode, Json<OrchestratorResponse>), ApiError> {
    if input.project_id.trim().is_empty() || input.goal.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "projectId and goal are required",
        ));
    }
    if input.goal.chars().count() > 20_000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "goal must be 20000 characters or fewer",
        ));
    }
    if input
        .cwd
        .as_deref()
        .is_some_and(|cwd| cwd.chars().count() > 1_000)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cwd must be 1000 characters or fewer",
        ));
    }
    let max_children = input.max_children.unwrap_or(4);
    if !(1..=8).contains(&max_children) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "maxChildren must be between 1 and 8",
        ));
    }
    let max_retries = input.max_retries.unwrap_or(1);
    if max_retries > 3 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "maxRetries must be between 0 and 3",
        ));
    }
    if input.max_seconds.is_some_and(|seconds| seconds < 60) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "maxSeconds must be at least 60",
        ));
    }
    let (auth, workspace_id) = auth_for_project(&state, &headers, &input.project_id).await?;
    require_workspace_permission(&state, &auth, &workspace_id, "project", "read").await?;
    require_workspace_permission(&state, &auth, &workspace_id, "task", "create").await?;
    require_workspace_permission(&state, &auth, &workspace_id, "task", "update").await?;
    let id = Uuid::new_v4().to_string();
    let project_cwd = project_local_path(&state.database, &input.project_id).await?;
    let cwd = resolve_orchestrator_cwd(input.cwd.as_deref(), project_cwd.as_deref(), &id)?;
    if !cwd.is_dir() {
        if input
            .cwd
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || project_cwd.is_some()
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "Orchestrator working directory is not a directory: {}",
                    cwd.display()
                ),
            ));
        }
        std::fs::create_dir_all(&cwd).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not create orchestrator working directory: {error}"),
            )
        })?;
    }
    let now = now_rfc3339();
    let record = OrchestratorRecord {
        id: id.clone(),
        parent_orchestrator_id: None,
        parent_child_id: None,
        depth: 0,
        workspace_id,
        project_id: input.project_id,
        credential: auth.credential.clone(),
        goal: input.goal.trim().to_string(),
        cwd,
        model: input.model,
        network_access: input.network_access.unwrap_or(false),
        max_children,
        max_retries,
        max_seconds: input
            .max_seconds
            .unwrap_or(RunnerConfig::default().default_max_seconds),
        status: OrchestratorStatus::Queued,
        created_at: now.clone(),
        updated_at: now,
        active_turn_id: None,
        error: None,
        cancel_requested: false,
        messages: vec![OrchestratorMessage {
            id: Uuid::new_v4().to_string(),
            role: "user".to_string(),
            text: input.goal.trim().to_string(),
            at: now_rfc3339(),
        }],
        children: Vec::new(),
    };
    {
        let mut orchestrators = state.orchestrators.lock().await;
        orchestrators.records.insert(id.clone(), record);
    }
    start_orchestrator_turn(&state, &auth, &id).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(orchestrator_snapshot(&state, &id).await?),
    ))
}

async fn get_orchestrator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<OrchestratorResponse>, ApiError> {
    let record = {
        let orchestrators = state.orchestrators.lock().await;
        orchestrators
            .records
            .get(&id)
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Orchestrator not found"))?
    };
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &record.workspace_id).await?;
    Ok(Json(orchestrator_snapshot(&state, &id).await?))
}

async fn message_orchestrator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<OrchestratorMessageInput>,
) -> Result<(StatusCode, Json<OrchestratorResponse>), ApiError> {
    if input.message.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "message is required",
        ));
    }
    if input.message.chars().count() > 20_000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "message must be 20000 characters or fewer",
        ));
    }
    let record = {
        let orchestrators = state.orchestrators.lock().await;
        orchestrators
            .records
            .get(&id)
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Orchestrator not found"))?
    };
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &record.workspace_id).await?;
    {
        let mut orchestrators = state.orchestrators.lock().await;
        refresh_orchestrator_tree(&mut orchestrators.records, &id, &state.orchestrator_runner);
        let record = orchestrators
            .records
            .get_mut(&id)
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Orchestrator not found"))?;
        if record.cancel_requested {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "Orchestrator has been cancelled",
            ));
        }
        if record.status == OrchestratorStatus::Running {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "Orchestrator is still working; wait for the current turn to finish",
            ));
        }
        append_orchestrator_message(record, "user", &input.message);
        record.error = None;
        record.updated_at = now_rfc3339();
    }
    start_orchestrator_turn(&state, &auth, &id).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(orchestrator_snapshot(&state, &id).await?),
    ))
}

async fn cancel_orchestrator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<OrchestratorResponse>, ApiError> {
    let record = {
        let orchestrators = state.orchestrators.lock().await;
        orchestrators
            .records
            .get(&id)
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Orchestrator not found"))?
    };
    let auth = authenticate(&state, &headers).await?;
    require_workspace(&state, &auth, &record.workspace_id).await?;
    let run_ids = {
        let mut orchestrators = state.orchestrators.lock().await;
        let mut run_ids = HashSet::new();
        cancel_orchestrator_tree(
            &mut orchestrators.records,
            &id,
            &mut run_ids,
            &mut HashSet::new(),
        );
        run_ids.into_iter().collect::<Vec<_>>()
    };
    for run_id in run_ids {
        let _ = state.orchestrator_runner.cancel(&run_id);
    }
    Ok(Json(orchestrator_snapshot(&state, &id).await?))
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

async fn native_auth_route(Path(path): Path<String>) -> Result<Response, ApiError> {
    Err(ApiError::new(
        StatusCode::BAD_REQUEST,
        format!("Optional authentication route /api/auth/{path} is not configured"),
    ))
}

async fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "message": "Kaneo route not found in the Rust runtime" })),
    )
        .into_response()
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/config", get(config))
        .route("/api/instance/status", get(instance_status))
        .route("/api/rust/status", get(rust_status))
        .route("/api/openapi", get(openapi))
        .route("/api/public-project/{id}", get(get_public_project))
        .route("/api/asset/{id}", get(get_asset))
        .route("/api/search", get(global_search))
        .route("/api/auth/get-session", get(get_session))
        .route("/api/oauth/id-token", get(get_oauth_id_token))
        .route("/api/auth/sign-up/email", post(sign_up_email))
        .route("/api/auth/sign-in/email", post(sign_in_email))
        .route("/api/auth/sign-in/anonymous", post(sign_in_anonymous))
        .route("/api/auth/sign-out", post(sign_out))
        .route("/api/auth/update-user", post(update_user))
        .route("/api/auth/change-password", post(change_password))
        .route("/api/auth/device", get(claim_device_code))
        .route("/api/auth/device/code", post(create_device_code))
        .route("/api/auth/device/approve", post(approve_device_code))
        .route("/api/auth/device/deny", post(deny_device_code))
        .route("/api/auth/device/token", post(device_token))
        .route("/api/auth/api-key/create", post(create_api_key))
        .route("/api/auth/api-key/list", get(list_api_keys))
        .route("/api/auth/api-key/delete", post(delete_api_key))
        .route("/api/mcp", get(mcp_get_endpoint).post(mcp_endpoint))
        .route(
            "/api/.well-known/oauth-protected-resource/api/mcp",
            get(mcp_protected_resource_metadata),
        )
        .route(
            "/api/.well-known/oauth-authorization-server/api",
            get(mcp_authorization_server_metadata),
        )
        .route("/api/mcp/register", post(mcp_register))
        .route("/api/mcp/authorize", get(mcp_authorize))
        .route(
            "/api/mcp/authorize/request/{request_id}",
            get(mcp_authorization_request).post(mcp_authorization_decision),
        )
        .route("/api/mcp/token", post(mcp_token))
        .route("/api/auth/organization/list", get(list_organizations))
        .route(
            "/api/auth/organization/list-invitations",
            get(list_invitations),
        )
        .route(
            "/api/auth/organization/list-user-invitations",
            get(list_user_invitations),
        )
        .route(
            "/api/auth/organization/get-invitation",
            get(get_organization_invitation),
        )
        .route("/api/auth/organization/invite-member", post(invite_member))
        .route("/api/auth/organization/remove-member", post(remove_member))
        .route(
            "/api/auth/organization/update-member-role",
            post(update_member_role),
        )
        .route(
            "/api/auth/organization/accept-invitation",
            post(accept_invitation),
        )
        .route(
            "/api/auth/organization/reject-invitation",
            post(reject_invitation),
        )
        .route(
            "/api/auth/organization/cancel-invitation",
            post(cancel_invitation),
        )
        .route("/api/auth/organization/list-roles", get(list_roles))
        .route("/api/auth/organization/create-role", post(create_role))
        .route("/api/auth/organization/update-role", post(update_role))
        .route("/api/auth/organization/delete-role", post(delete_role))
        .route("/api/auth/organization/create", post(create_organization))
        .route(
            "/api/auth/organization/set-active",
            post(set_active_organization),
        )
        .route("/api/auth/organization/update", post(update_organization))
        .route("/api/auth/organization/delete", post(delete_organization))
        .route("/api/auth/organization/list-members", get(list_members))
        .route(
            "/api/auth/organization/get-active-member",
            get(get_active_member),
        )
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
        .route(
            "/api/slack-integration/project/{project_id}",
            get(get_slack_integration)
                .post(create_slack_integration)
                .patch(update_slack_integration)
                .delete(delete_slack_integration),
        )
        .route(
            "/api/discord-integration/project/{project_id}",
            get(get_discord_integration)
                .post(create_discord_integration)
                .patch(update_discord_integration)
                .delete(delete_discord_integration),
        )
        .route(
            "/api/telegram-integration/project/{project_id}",
            get(get_telegram_integration)
                .post(create_telegram_integration)
                .patch(update_telegram_integration)
                .delete(delete_telegram_integration),
        )
        .route("/api/github-integration/app-info", get(github_app_info))
        .route(
            "/api/github-integration/repositories",
            get(list_github_repositories),
        )
        .route(
            "/api/github-integration/verify",
            post(verify_github_installation),
        )
        .route(
            "/api/github-integration/import-issues",
            post(import_github_issues),
        )
        .route("/api/github-integration/webhook", post(github_webhook))
        .route(
            "/api/github-integration/project/{project_id}",
            get(get_github_integration)
                .post(create_github_integration)
                .patch(update_github_integration)
                .delete(delete_github_integration),
        )
        .route(
            "/api/gitea-integration/repositories",
            post(list_gitea_repositories),
        )
        .route("/api/gitea-integration/verify", post(verify_gitea_access))
        .route(
            "/api/gitea-integration/project/{project_id}",
            get(get_gitea_integration)
                .post(create_gitea_integration)
                .patch(update_gitea_integration)
                .delete(delete_gitea_integration),
        )
        .route(
            "/api/gitea-integration/import-issues",
            post(import_gitea_issues),
        )
        .route(
            "/api/gitea-integration/webhook/{integration_id}",
            post(gitea_webhook),
        )
        .route("/api/invitation/pending", get(pending_invitations))
        .route(
            "/api/invitation/public/{id}",
            get(public_invitation_details),
        )
        .route("/api/billing/webhook", post(billing_webhook))
        .route(
            "/api/billing/{workspace_id}/checkout",
            post(create_billing_checkout),
        )
        .route(
            "/api/billing/{workspace_id}/portal",
            post(create_billing_portal),
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
        .route("/api/task/image-upload/{id}", put(create_task_image_upload))
        .route(
            "/api/task/image-upload/{id}/finalize",
            post(finalize_task_image_upload),
        )
        .route("/api/task/move/{id}", put(move_task))
        .route("/api/task/export/{project_id}", get(export_tasks))
        .route("/api/agent/runs", post(start_agent))
        .route("/api/agent/runs/{id}", get(get_agent))
        .route("/api/agent/runs/{id}/cancel", post(cancel_agent))
        .route("/api/agent/orchestrators", post(create_orchestrator))
        .route("/api/agent/orchestrators/{id}", get(get_orchestrator))
        .route(
            "/api/agent/orchestrators/{id}/messages",
            post(message_orchestrator),
        )
        .route(
            "/api/agent/orchestrators/{id}/cancel",
            post(cancel_orchestrator),
        )
        .route(
            "/api/auth/{*path}",
            get(native_auth_route)
                .post(native_auth_route)
                .put(native_auth_route)
                .patch(native_auth_route)
                .delete(native_auth_route),
        )
        .fallback(not_found)
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
    let client_url = env::var("KANEO_CLIENT_URL")
        .unwrap_or_else(|_| "http://localhost:5173".to_string())
        .trim_end_matches('/')
        .to_string();
    let (events, _) = broadcast::channel(512);
    let orchestrator_max_active_runs = env::var("KANEO_ORCHESTRATOR_MAX_ACTIVE_RUNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(16);
    let state = AppState {
        database,
        runner: RunManager::new(RunnerConfig::default()),
        orchestrator_runner: RunManager::new(RunnerConfig {
            max_active_runs: orchestrator_max_active_runs,
            ..RunnerConfig::default()
        }),
        orchestrators: Arc::new(Mutex::new(OrchestratorState::default())),
        http: reqwest::Client::new(),
        api_base_url: env::var("KANEO_API_URL")
            .unwrap_or_else(|_| format!("http://{bind}"))
            .trim_end_matches('/')
            .to_string(),
        client_url,
        mcp: Arc::new(Mutex::new(McpState::default())),
        events,
    };
    let listener = TcpListener::bind(&bind).await?;
    eprintln!("[kaneo-rust-api] listening on http://{bind}");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_orchestrator() -> OrchestratorRecord {
        OrchestratorRecord {
            id: "orchestrator-test".to_string(),
            parent_orchestrator_id: None,
            parent_child_id: None,
            depth: 0,
            workspace_id: "workspace-test".to_string(),
            project_id: "project-test".to_string(),
            credential: "secret".to_string(),
            goal: "Ship the test project".to_string(),
            cwd: std::env::current_dir().expect("current directory"),
            model: Some("gpt-test".to_string()),
            network_access: false,
            max_children: 3,
            max_retries: 1,
            max_seconds: 60,
            status: OrchestratorStatus::Queued,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            active_turn_id: None,
            error: None,
            cancel_requested: false,
            messages: vec![OrchestratorMessage {
                id: "message-test".to_string(),
                role: "user".to_string(),
                text: "Ship the test project".to_string(),
                at: now_rfc3339(),
            }],
            children: Vec::new(),
        }
    }

    #[test]
    fn orchestrator_prompt_contains_delegation_contract() {
        let record = test_orchestrator();
        let prompt = build_orchestrator_prompt(&record);
        assert!(prompt.contains("orchestrator_delegate"));
        assert!(prompt.contains("orchestrator_children"));
        assert!(prompt.contains("orchestrator-test"));
        assert!(prompt.contains("Ship the test project"));
    }

    #[test]
    fn mcp_lists_orchestrator_tools() {
        let definitions = mcp_tool_definitions();
        let tools = definitions.as_array().expect("tool list is an array");
        for expected in [
            "orchestrator_status",
            "orchestrator_children",
            "orchestrator_delegate",
        ] {
            assert!(
                tools
                    .iter()
                    .any(|tool| tool.get("name").and_then(Value::as_str) == Some(expected)),
                "missing MCP tool {expected}"
            );
        }
    }

    #[test]
    fn project_local_path_accepts_existing_absolute_directory() {
        let current = std::env::current_dir()
            .expect("current directory")
            .display()
            .to_string();
        assert_eq!(
            validate_project_local_path(Some(current.clone())).expect("valid path"),
            Some(current)
        );
        assert_eq!(
            validate_project_local_path(None).expect("missing path"),
            None
        );
        assert!(validate_project_local_path(Some("relative/project".to_string())).is_err());
    }

    #[test]
    fn project_local_path_is_the_default_agent_working_directory() {
        let project_path = std::env::current_dir()
            .expect("current directory")
            .display()
            .to_string();
        let input = StartAgentInput {
            project_id: "project-test".to_string(),
            prompt: "test".to_string(),
            cwd: None,
            model: None,
            network_access: None,
            max_seconds: None,
        };
        let cwd = resolve_agent_cwd(&input, Some(&project_path), "run-test")
            .expect("project path should be selected");
        assert_eq!(cwd, FsPath::new(&project_path));
    }

    #[test]
    fn refresh_without_active_runs_waits_for_input() {
        let mut record = test_orchestrator();
        let runner = RunManager::new(RunnerConfig::default());
        refresh_orchestrator_status(&mut record, &runner, &HashMap::new());
        assert_eq!(record.status, OrchestratorStatus::Waiting);
    }

    #[test]
    fn nested_orchestrator_response_contains_the_execution_tree() {
        let mut root = test_orchestrator();
        root.children.push(OrchestratorChild {
            id: "child-link".to_string(),
            orchestrator_id: Some("child-orchestrator".to_string()),
            task_id: Some("task-child".to_string()),
            prompt: "Deliver the child task".to_string(),
            cwd: root.cwd.clone(),
            model: root.model.clone(),
            network_access: false,
            max_seconds: 60,
            attempt: 1,
            max_retries: 1,
            run_id: "child-run".to_string(),
            status: RunStatus::Completed,
            error: None,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
        });
        let nested = OrchestratorRecord {
            id: "child-orchestrator".to_string(),
            parent_orchestrator_id: Some(root.id.clone()),
            parent_child_id: Some("child-link".to_string()),
            depth: 1,
            workspace_id: root.workspace_id.clone(),
            project_id: root.project_id.clone(),
            credential: root.credential.clone(),
            goal: "Deliver the child task".to_string(),
            cwd: root.cwd.clone(),
            model: root.model.clone(),
            network_access: false,
            max_children: 3,
            max_retries: 1,
            max_seconds: 60,
            status: OrchestratorStatus::Running,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            active_turn_id: Some("child-run".to_string()),
            error: None,
            cancel_requested: false,
            messages: Vec::new(),
            children: Vec::new(),
        };
        let mut records = HashMap::from([(root.id.clone(), root), (nested.id.clone(), nested)]);
        let runner = RunManager::new(RunnerConfig::default());
        refresh_orchestrator_tree(&mut records, "orchestrator-test", &runner);
        let response = orchestrator_response(
            records.get("orchestrator-test").expect("root record"),
            &runner,
            &records,
        );
        let child = response.children.first().expect("child response");
        let nested_response = child
            .orchestrator
            .as_ref()
            .expect("nested orchestrator response");
        assert_eq!(child.orchestrator_id.as_deref(), Some("child-orchestrator"));
        assert_eq!(nested_response.id, "child-orchestrator");
        assert_eq!(
            nested_response.parent_orchestrator_id.as_deref(),
            Some("orchestrator-test")
        );
        assert_eq!(nested_response.depth, 1);
        assert_eq!(nested_response.status, OrchestratorStatus::Waiting);
    }

    #[test]
    fn nested_spec_uses_child_context_id() {
        let record = test_orchestrator();
        let spec = build_orchestrator_spec(
            &record,
            "run-child".to_string(),
            "child prompt".to_string(),
            record.cwd.clone(),
            record.model.clone(),
            false,
            60,
            "child-orchestrator",
            Some(&record.id),
            Some("child-link"),
            Some("task-child"),
        );
        assert_eq!(
            spec.environment.get("KANEO_ORCHESTRATOR_ID"),
            Some(&"child-orchestrator".to_string())
        );
        assert_eq!(
            spec.environment.get("KANEO_PARENT_ORCHESTRATOR_ID"),
            Some(&"orchestrator-test".to_string())
        );
    }
}
