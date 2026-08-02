use kaneo_core::{AgentSpec, RunManager, RunStatus, RunnerConfig};
use std::collections::BTreeMap;
use std::thread;
use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        eprintln!("usage: kaneo-agent <command> [args ...]");
        std::process::exit(2);
    };

    let spec = AgentSpec {
        id: None,
        workspace_id: "local".to_string(),
        project_id: "local".to_string(),
        prompt: "local Rust runner invocation".to_string(),
        cwd: std::env::current_dir().expect("current directory"),
        model: None,
        network_access: false,
        command,
        command_args: args.collect(),
        environment: BTreeMap::new(),
        max_seconds: RunnerConfig::default().default_max_seconds,
    };

    let manager = RunManager::new(RunnerConfig::default());
    let run = manager.start(spec).unwrap_or_else(|error| {
        eprintln!("could not start run: {error}");
        std::process::exit(1);
    });
    let id = run.id.clone();

    loop {
        let run = manager.get(&id).expect("runner retained the run");
        println!("{}", serde_json::to_string(&run).expect("serialize run"));
        if !run.status.is_active() {
            std::process::exit(match run.status {
                RunStatus::Completed => 0,
                RunStatus::Queued
                | RunStatus::Running
                | RunStatus::Failed
                | RunStatus::Cancelled => 1,
            });
        }
        thread::sleep(Duration::from_millis(100));
    }
}
