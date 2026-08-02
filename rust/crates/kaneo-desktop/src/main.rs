use std::env;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use axum::Router;
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};
use url::Url;

struct ApiChild(Mutex<Option<Child>>);

fn configured_api_binary() -> String {
    if let Ok(path) = env::var("KANEO_RUST_API_BIN") {
        if !path.trim().is_empty() {
            return path;
        }
    }
    let current = env::current_exe().expect("could not resolve the Kaneo desktop executable");
    current
        .parent()
        .expect("Kaneo desktop executable has no parent")
        .join("kaneo-api")
        .display()
        .to_string()
}

fn start_api() -> Result<Child, String> {
    let binary = configured_api_binary();
    let mut command = Command::new(&binary);
    command
        .envs(env::vars())
        .env(
            "KANEO_RUST_BIND",
            env::var("KANEO_RUST_BIND").unwrap_or_else(|_| "127.0.0.1:1337".to_string()),
        )
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command.spawn().map_err(|error| {
        format!(
            "Could not start the Rust Kaneo API at {binary}: {error}. Set KANEO_RUST_API_BIN to the built kaneo-api binary."
        )
    })
}

fn web_url() -> Result<Url, String> {
    let value = env::var("KANEO_WEB_URL").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string());
    Url::parse(&value).map_err(|error| format!("Invalid KANEO_WEB_URL: {error}"))
}

fn web_root() -> Option<PathBuf> {
    if let Ok(root) = env::var("KANEO_WEB_ROOT") {
        let path = PathBuf::from(root);
        if path.join("index.html").is_file() {
            return Some(path);
        }
    }
    let current = env::current_exe().ok()?;
    let runtime_root = current.parent()?.parent()?;
    let bundled_root = runtime_root.join("web");
    bundled_root
        .join("index.html")
        .is_file()
        .then_some(bundled_root)
}

fn start_web_server() {
    let Some(root) = web_root() else {
        eprintln!(
            "[kaneo-rust-desktop] no bundled web root; using an already-running KANEO_WEB_URL"
        );
        return;
    };
    let port = env::var("KANEO_WEB_PORT").unwrap_or_else(|_| "5173".to_string());
    std::thread::Builder::new()
        .name("kaneo-web".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("could not create the Kaneo web runtime");
            runtime.block_on(async move {
                let listener = match TcpListener::bind(format!("127.0.0.1:{port}")).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        eprintln!(
                            "[kaneo-rust-desktop] web server could not bind port {port}: {error}"
                        );
                        return;
                    }
                };
                let index = root.join("index.html");
                let service = ServeDir::new(&root).not_found_service(ServeFile::new(index));
                if let Err(error) =
                    axum::serve(listener, Router::new().fallback_service(service)).await
                {
                    eprintln!("[kaneo-rust-desktop] web server stopped: {error}");
                }
            });
        })
        .expect("could not create the Kaneo web server thread");
}

fn create_window(app: &AppHandle) -> Result<(), String> {
    WebviewWindowBuilder::new(app, "main", WebviewUrl::External(web_url()?))
        .title("Kaneo")
        .inner_size(1440.0, 960.0)
        .min_inner_size(960.0, 640.0)
        .build()
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let api = start_api().map_err(std::io::Error::other)?;
            app.manage(ApiChild(Mutex::new(Some(api))));
            start_web_server();
            std::thread::sleep(Duration::from_millis(100));
            create_window(app.handle()).map_err(std::io::Error::other)?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the Kaneo Tauri application")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(child) = app.try_state::<ApiChild>() {
                    if let Ok(mut child) = child.0.lock() {
                        if let Some(mut child) = child.take() {
                            let _ = child.kill();
                        }
                    }
                }
            }
        });
}
