# Kaneo Rust migration

This workspace is the beginning of the full Kaneo migration into one Rust
project. It now includes the performance-sensitive agent process boundary,
an authenticated PostgreSQL HTTP runtime for the board and task flows, and a
Tauri desktop shell that starts the Rust API and can serve the built web app.

The Rust API also owns the board's live project WebSocket, project and column
CRUD, public-project reads, workspace member reads, workflow-rule CRUD, global
search, label CRUD and assignment, task label reads, task field updates,
cross-project move/export/import and bulk operations, external-link reads,
activity and comment CRUD, task-relation CRUD, time-entry CRUD, organization
membership and permission reads, notification inbox operations, pending
invitations and public invitation details, custom-OAuth id-token reads, and
workspace billing state. It also owns notification preference and workspace-rule
CRUD, including the existing AES-256-GCM secret format. Native notification
creation applies the same task preference gates and emits the user-socket
invalidation event. Task, comment,
relation, label, and time-entry mutations publish filtered events to connected
project boards, so an agent changing a task is visible without waiting for a
polling cycle.

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
