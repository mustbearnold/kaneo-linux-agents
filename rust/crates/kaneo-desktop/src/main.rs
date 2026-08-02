use std::env;
use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use axum::Router;
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};
use url::Url;

struct ApiChild(Mutex<Option<Child>>);

fn configure_linux_webview() {
    #[cfg(target_os = "linux")]
    {
        // WebKitGTK's accelerated compositor can fail to create a GBM surface
        // on some Linux GPU/Wayland combinations, leaving the native window
        // completely white. Keep an explicit user setting intact, but make
        // the packaged app render reliably by default.
        if env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
            unsafe {
                env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
            }
        }
    }
}

fn load_default_environment(resource_dir: Option<&Path>) {
    let Some(resource_dir) = resource_dir else {
        return;
    };
    let path = resource_dir.join("default.env");
    let Ok(contents) = fs::read_to_string(&path) else {
        return;
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().strip_prefix("export ").unwrap_or(key.trim());
        if key.is_empty() || env::var_os(key).is_some() {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(value);
        unsafe {
            env::set_var(key, value);
        }
    }
}

fn configured_api_binary(resource_dir: Option<&Path>) -> String {
    if let Ok(path) = env::var("KANEO_RUST_API_BIN") {
        if !path.trim().is_empty() {
            return path;
        }
    }
    if let Some(resource_dir) = resource_dir {
        let bundled = resource_dir.join("kaneo-api");
        if bundled.is_file() {
            return bundled.display().to_string();
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

fn start_api(resource_dir: Option<&Path>) -> Result<Child, String> {
    let binary = configured_api_binary(resource_dir);
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

fn web_root(app: &AppHandle) -> Option<PathBuf> {
    if let Ok(root) = env::var("KANEO_WEB_ROOT") {
        let path = PathBuf::from(root);
        if path.join("index.html").is_file() {
            return Some(path);
        }
    }
    if let Ok(resource_dir) = app.path().resource_dir() {
        let bundled_root = resource_dir.join("web");
        if bundled_root.join("index.html").is_file() {
            return Some(bundled_root);
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

fn start_web_server(app: &AppHandle) -> Option<String> {
    let Some(root) = web_root(app) else {
        eprintln!(
            "[kaneo-rust-desktop] no bundled web root; using an already-running KANEO_WEB_URL"
        );
        return None;
    };
    let port = env::var("KANEO_WEB_PORT").unwrap_or_else(|_| "5173".to_string());
    let ready_port = port.clone();
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
    Some(ready_port)
}

fn wait_for_web_server(port: &str) {
    for _ in 0..100 {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    eprintln!("[kaneo-rust-desktop] web server did not become ready on port {port}");
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
    configure_linux_webview();
    tauri::Builder::default()
        .setup(|app| {
            let resource_dir = app.path().resource_dir().ok();
            load_default_environment(resource_dir.as_deref());
            let api = start_api(resource_dir.as_deref()).map_err(std::io::Error::other)?;
            app.manage(ApiChild(Mutex::new(Some(api))));
            if let Some(port) = start_web_server(app.handle()) {
                wait_for_web_server(&port);
            }
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
