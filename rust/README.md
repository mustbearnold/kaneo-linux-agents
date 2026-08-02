# Kaneo Rust migration

This workspace is the beginning of the full Kaneo migration into one Rust
project. It now includes the performance-sensitive agent process boundary,
an authenticated PostgreSQL HTTP runtime for the board and task flows, and a
Tauri desktop shell that starts the Rust API and can serve the built web app.

The Rust API also owns the board's live project WebSocket, task label reads,
external-link reads, organization membership and permission reads, notification
inbox operations, pending invitations, and workspace billing state. Task
mutations publish filtered events to connected project boards, so an agent
changing a task is visible without waiting for a polling cycle.

The current TypeScript API remains a compatibility runtime while feature parity
is built in Rust. In packaged Electron builds it runs privately on port 1338;
the Rust API owns port 1337 and proxies only the routes that have not moved.
The intended end state is a Rust Kaneo core and API shared by the desktop shell
and web client, with no duplicate agent scheduler.

Run the first migration gate with:

```sh
cargo test --manifest-path rust/Cargo.toml
```

Build the two native desktop components with:

```sh
cargo build --manifest-path rust/Cargo.toml --release -p kaneo-api -p kaneo-desktop
```

`kaneo-api` authenticates Better Auth session cookies and API keys directly
against the existing schema, serves board/project/task routes, publishes live
task events, and runs Codex through `kaneo-core`. `kaneo-desktop` starts that
API, serves the web bundle from a sibling `web/` directory when present, and
opens it in a native Tauri window. Set `KANEO_WEB_ROOT` when running the shell
from a development checkout.
