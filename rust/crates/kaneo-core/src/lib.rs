//! The first Rust slice of Kaneo: a bounded, observable agent-run core.
//!
//! The existing TypeScript API remains the compatibility surface while the
//! rest of Kaneo is migrated. This crate deliberately has no web framework or
//! database dependency so it can become the shared core for the API, desktop
//! shell, and worker process without pulling UI concerns into the scheduler.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Formatter};
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const DEFAULT_MAX_ACTIVE_RUNS: usize = 2;
pub const DEFAULT_MAX_EVENTS: usize = 1_000;
pub const DEFAULT_MAX_EVENT_TEXT: usize = 12_000;
pub const DEFAULT_MAX_SECONDS: u64 = 60 * 60;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl RunStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Queued | Self::Running)
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentEvent {
    pub at: String,
    pub event_type: String,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentRun {
    pub id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub prompt: String,
    pub cwd: String,
    pub model: Option<String>,
    pub network_access: bool,
    pub status: RunStatus,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub events: Vec<AgentEvent>,
}

#[derive(Debug, Clone)]
pub struct AgentSpec {
    pub id: Option<String>,
    pub workspace_id: String,
    pub project_id: String,
    pub prompt: String,
    pub cwd: PathBuf,
    pub model: Option<String>,
    pub network_access: bool,
    pub command: String,
    pub command_args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub max_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub max_active_runs: usize,
    pub max_events: usize,
    pub max_event_text: usize,
    pub default_max_seconds: u64,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            max_active_runs: DEFAULT_MAX_ACTIVE_RUNS,
            max_events: DEFAULT_MAX_EVENTS,
            max_event_text: DEFAULT_MAX_EVENT_TEXT,
            default_max_seconds: DEFAULT_MAX_SECONDS,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum StartError {
    AtCapacity { max_active_runs: usize },
    InvalidWorkingDirectory(String),
}

impl Display for StartError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AtCapacity { max_active_runs } => write!(
                formatter,
                "Kaneo already has the maximum number of active agent runs ({max_active_runs})."
            ),
            Self::InvalidWorkingDirectory(path) => {
                write!(
                    formatter,
                    "Agent working directory is not a directory: {path}"
                )
            }
        }
    }
}

impl std::error::Error for StartError {}

struct RunnerState {
    runs: HashMap<String, AgentRun>,
    children: HashMap<String, Arc<Mutex<Option<Child>>>>,
}

#[derive(Clone)]
pub struct RunManager {
    state: Arc<Mutex<RunnerState>>,
    config: RunnerConfig,
}

impl RunManager {
    pub fn new(config: RunnerConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(RunnerState {
                runs: HashMap::new(),
                children: HashMap::new(),
            })),
            config,
        }
    }

    pub fn start(&self, spec: AgentSpec) -> Result<AgentRun, StartError> {
        if !spec.cwd.is_dir() {
            return Err(StartError::InvalidWorkingDirectory(
                spec.cwd.display().to_string(),
            ));
        }

        let mut state = self.state.lock().expect("runner state lock poisoned");
        let active_runs = state
            .runs
            .values()
            .filter(|run| run.status.is_active())
            .count();
        if active_runs >= self.config.max_active_runs {
            return Err(StartError::AtCapacity {
                max_active_runs: self.config.max_active_runs,
            });
        }

        let id = spec
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let created_at = now();
        let run = AgentRun {
            id: id.clone(),
            workspace_id: spec.workspace_id.clone(),
            project_id: spec.project_id.clone(),
            prompt: spec.prompt.clone(),
            cwd: spec.cwd.display().to_string(),
            model: spec.model.clone(),
            network_access: spec.network_access,
            status: RunStatus::Queued,
            created_at,
            started_at: None,
            finished_at: None,
            exit_code: None,
            error: None,
            events: Vec::new(),
        };
        state.runs.insert(id.clone(), run.clone());
        drop(state);

        let state = Arc::clone(&self.state);
        let config = self.config.clone();
        thread::Builder::new()
            .name(format!("kaneo-agent-{id}"))
            .spawn(move || execute_run(id, spec, state, config))
            .expect("failed to spawn Kaneo agent worker");

        Ok(run)
    }

    pub fn get(&self, id: &str) -> Option<AgentRun> {
        self.state
            .lock()
            .expect("runner state lock poisoned")
            .runs
            .get(id)
            .cloned()
    }

    pub fn cancel(&self, id: &str) -> Option<AgentRun> {
        let child = {
            let mut state = self.state.lock().expect("runner state lock poisoned");
            let run = state.runs.get_mut(id)?;
            if !run.status.is_active() {
                return Some(run.clone());
            }
            run.status = RunStatus::Cancelled;
            run.finished_at = Some(now());
            state.children.get(id).cloned()
        };

        if let Some(child) = child {
            if let Ok(mut child) = child.lock() {
                if let Some(child) = child.as_mut() {
                    let _ = child.kill();
                }
            }
        }

        self.get(id)
    }

    pub fn active_count(&self) -> usize {
        self.state
            .lock()
            .expect("runner state lock poisoned")
            .runs
            .values()
            .filter(|run| run.status.is_active())
            .count()
    }
}

fn execute_run(id: String, spec: AgentSpec, state: Arc<Mutex<RunnerState>>, config: RunnerConfig) {
    update_run(&state, &id, |run| {
        run.status = RunStatus::Running;
        run.started_at = Some(now());
        append_event(
            run,
            "run.started",
            &format!("Agent started in {}.", spec.cwd.display()),
            &config,
        );
    });

    let mut command = Command::new(&spec.command);
    command
        .args(&spec.command_args)
        .current_dir(&spec.cwd)
        .envs(&spec.environment)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            finish_failed(
                &state,
                &id,
                format!("Could not start agent: {error}"),
                &config,
            );
            return;
        }
    };
    let child = Arc::new(Mutex::new(Some(child)));
    state
        .lock()
        .expect("runner state lock poisoned")
        .children
        .insert(id.clone(), Arc::clone(&child));

    let (output_sender, output_receiver) = mpsc::channel();
    let stdout = child
        .lock()
        .expect("child lock poisoned")
        .as_mut()
        .and_then(|child| child.stdout.take());
    let stderr = child
        .lock()
        .expect("child lock poisoned")
        .as_mut()
        .and_then(|child| child.stderr.take());
    if let Some(stdout) = stdout {
        spawn_reader(stdout, "stdout", output_sender.clone());
    }
    if let Some(stderr) = stderr {
        spawn_reader(stderr, "stderr", output_sender.clone());
    }
    drop(output_sender);

    let max_seconds = if spec.max_seconds == 0 {
        config.default_max_seconds
    } else {
        spec.max_seconds.min(24 * 60 * 60)
    };
    let deadline = Instant::now() + Duration::from_secs(max_seconds);
    let mut timed_out = false;
    let exit_status = loop {
        while let Ok(output) = output_receiver.try_recv() {
            add_output(&state, &id, output, &config);
        }

        let cancelled = state
            .lock()
            .expect("runner state lock poisoned")
            .runs
            .get(&id)
            .is_some_and(|run| run.status == RunStatus::Cancelled);
        if cancelled {
            kill_child(&child);
        }
        if !timed_out && Instant::now() >= deadline {
            timed_out = true;
            update_run(&state, &id, |run| {
                let error = format!("Agent run exceeded {max_seconds} seconds.");
                run.error = Some(error.clone());
                append_event(run, "timeout", &error, &config);
            });
            kill_child(&child);
        }

        let status = child
            .lock()
            .expect("child lock poisoned")
            .as_mut()
            .and_then(|child| child.try_wait().ok().flatten());
        if status.is_some() {
            break status;
        }
        thread::sleep(Duration::from_millis(25));
    };

    while let Ok(output) = output_receiver.try_recv() {
        add_output(&state, &id, output, &config);
    }

    let exit_code = exit_status.and_then(|status| status.code());
    let mut state = state.lock().expect("runner state lock poisoned");
    state.children.remove(&id);
    if let Some(child) = child.lock().expect("child lock poisoned").take() {
        drop(child);
    }
    if let Some(run) = state.runs.get_mut(&id) {
        run.exit_code = exit_code;
        run.finished_at = Some(now());
        if run.status == RunStatus::Cancelled {
            append_event(run, "run.cancelled", "Agent run cancelled.", &config);
        } else if timed_out || exit_status.is_none_or(|status| !status.success()) {
            run.status = RunStatus::Failed;
            if run.error.is_none() {
                run.error = Some(match exit_status {
                    Some(status) => format_exit_status(status),
                    None => "Agent process ended without an exit status.".to_string(),
                });
            }
            let error = run
                .error
                .clone()
                .unwrap_or_else(|| "Agent failed.".to_string());
            append_event(run, "run.failed", &error, &config);
        } else {
            run.status = RunStatus::Completed;
            append_event(
                run,
                "run.completed",
                "Agent run completed successfully.",
                &config,
            );
        }
    }
}

struct OutputLine {
    stream: &'static str,
    line: String,
}

fn spawn_reader<R: Read + Send + 'static>(
    reader: R,
    stream: &'static str,
    sender: mpsc::Sender<OutputLine>,
) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let _ = sender.send(OutputLine { stream, line });
        }
    });
}

fn add_output(
    state: &Arc<Mutex<RunnerState>>,
    id: &str,
    output: OutputLine,
    config: &RunnerConfig,
) {
    let (event_type, text) = parse_output(&output.line, output.stream);
    update_run(state, id, |run| {
        append_event(run, &event_type, &text, config)
    });
}

fn parse_output(line: &str, stream: &str) -> (String, String) {
    let trimmed = line.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let event_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("event")
            .to_string();
        let text = value
            .get("item")
            .and_then(|item| {
                item.get("text")
                    .or_else(|| item.get("message"))
                    .or_else(|| item.get("content"))
            })
            .or_else(|| value.get("message"))
            .or_else(|| value.get("error"))
            .map(value_text)
            .unwrap_or_else(|| trimmed.to_string());
        return (event_type, text);
    }
    (stream.to_string(), trimmed.to_string())
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    }
}

fn update_run<F>(state: &Arc<Mutex<RunnerState>>, id: &str, update: F)
where
    F: FnOnce(&mut AgentRun),
{
    if let Some(run) = state
        .lock()
        .expect("runner state lock poisoned")
        .runs
        .get_mut(id)
    {
        update(run);
    }
}

fn finish_failed(state: &Arc<Mutex<RunnerState>>, id: &str, error: String, config: &RunnerConfig) {
    update_run(state, id, |run| {
        run.status = RunStatus::Failed;
        run.error = Some(error.clone());
        run.finished_at = Some(now());
        append_event(run, "run.error", &error, config);
        append_event(run, "run.failed", &error, config);
    });
}

fn append_event(run: &mut AgentRun, event_type: &str, text: &str, config: &RunnerConfig) {
    let text = redact_secrets(text);
    let text = text.chars().take(config.max_event_text).collect();
    run.events.push(AgentEvent {
        at: now(),
        event_type: event_type.to_string(),
        text,
    });
    if run.events.len() > config.max_events {
        let remove = run.events.len() - config.max_events;
        run.events.drain(0..remove);
    }
}

pub fn redact_secrets(text: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<Value>(text) {
        redact_json(&mut value);
        return serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_string());
    }

    let mut result = text.to_string();
    for prefix in ["Bearer ", "bearer "] {
        if let Some(start) = result.find(prefix) {
            let token_start = start + prefix.len();
            let token_end = result[token_start..]
                .find(char::is_whitespace)
                .map(|offset| token_start + offset)
                .unwrap_or(result.len());
            result.replace_range(token_start..token_end, "[redacted]");
        }
    }
    result
}

fn redact_json(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                let lower = key.to_ascii_lowercase();
                if lower.contains("token")
                    || lower.contains("api_key")
                    || lower.contains("access_key")
                {
                    *value = Value::String("[redacted]".to_string());
                } else {
                    redact_json(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(redact_json),
        _ => {}
    }
}

fn kill_child(child: &Arc<Mutex<Option<Child>>>) {
    if let Ok(mut child) = child.lock() {
        if let Some(child) = child.as_mut() {
            let _ = child.kill();
        }
    }
}

fn format_exit_status(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("Agent exited with code {code}."),
        None => "Agent exited without a code.".to_string(),
    }
}

fn now() -> String {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    milliseconds.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn shell_spec(id: &str, script: &str) -> AgentSpec {
        AgentSpec {
            id: Some(id.to_string()),
            workspace_id: "workspace".to_string(),
            project_id: "project".to_string(),
            prompt: "test".to_string(),
            cwd: std::env::current_dir().expect("current directory"),
            model: None,
            network_access: false,
            command: "sh".to_string(),
            command_args: vec!["-c".to_string(), script.to_string()],
            environment: BTreeMap::new(),
            max_seconds: 5,
        }
    }

    fn wait_for_terminal(manager: &RunManager, id: &str) -> AgentRun {
        for _ in 0..200 {
            let run = manager.get(id).expect("run exists");
            if !run.status.is_active() {
                return run;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("run did not finish");
    }

    #[test]
    fn redacts_sensitive_json_and_bearer_output() {
        let redacted = redact_secrets(r#"{"token":"secret","nested":{"api_key":"hidden"}}"#);
        assert!(!redacted.contains("secret"));
        assert!(!redacted.contains("hidden"));
        assert!(redacted.contains("[redacted]"));
        assert_eq!(redact_secrets("Bearer super-secret"), "Bearer [redacted]");
    }

    #[test]
    fn enforces_the_active_run_bound() {
        let manager = RunManager::new(RunnerConfig {
            max_active_runs: 1,
            ..RunnerConfig::default()
        });
        manager
            .start(shell_spec("first", "sleep 0.15"))
            .expect("first run starts");
        assert_eq!(
            manager.start(shell_spec("second", "true")),
            Err(StartError::AtCapacity { max_active_runs: 1 })
        );
        let run = wait_for_terminal(&manager, "first");
        assert_eq!(run.status, RunStatus::Completed);
    }

    #[test]
    fn runs_independent_jobs_in_parallel() {
        let manager = RunManager::new(RunnerConfig {
            max_active_runs: 2,
            ..RunnerConfig::default()
        });
        let started = Instant::now();
        manager
            .start(shell_spec("first", "sleep 0.20"))
            .expect("first run starts");
        manager
            .start(shell_spec("second", "sleep 0.20"))
            .expect("second run starts");
        let first = wait_for_terminal(&manager, "first");
        let second = wait_for_terminal(&manager, "second");
        assert_eq!(first.status, RunStatus::Completed);
        assert_eq!(second.status, RunStatus::Completed);
        assert!(started.elapsed() < Duration::from_millis(380));
    }
}
