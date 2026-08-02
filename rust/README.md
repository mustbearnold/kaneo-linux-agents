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
invalidation event. Generic-webhook configuration CRUD is native as well;
outbound delivery is dispatched by the Rust runtime. Task, comment,
relation, label, and time-entry mutations publish filtered events to connected
project boards, so an agent changing a task is visible without waiting for a
polling cycle.

The Rust API also serves the authenticated `/api/mcp` JSON-RPC endpoint and its
protected-resource metadata. It exposes the project, task, comment, label, and
relation tools used by autonomous agents through the same session or API-key
credential, so the agent-to-board path no longer depends on the TypeScript MCP
server. The Rust runtime also owns dynamic client registration, trusted-origin
consent, and PKCE authorization-code exchange; its in-memory OAuth state has the
same restart semantics as the legacy implementation.

Native agent runs enforce the project/task permission boundary, validate prompt
and runtime limits, and inject the local
Rust MCP URL into each Codex invocation. An agent launched by the Rust API can
therefore use the board bridge without relying on a pre-existing Codex MCP
configuration.

Slack, Discord, and Telegram project-integration configuration is native too:
the Rust API validates webhook or bot credentials, preserves event settings,
returns masked secrets, and dispatches configured task events directly.

GitHub and Gitea project-integration settings are native as well. The Rust API
handles project-scoped CRUD, workspace permissions, repository conflict checks,
Gitea token and repository verification, repository listing, masked tokens, and
webhook URL generation, GitHub App repository discovery and verification, issue
import, and both providers' inbound webhook handlers. Creem billing checkout,
customer portal links, and signed webhook processing are native too.

The desktop package has one API runtime: the Rust server owns the HTTP origin,
database access, integrations, WebSockets, and autonomous agent execution. The
web client is still the browser UI, but no Node API process is started or
required by the desktop shell.

Run the first migration gate with:

```sh
cargo test --manifest-path rust/Cargo.toml
```

Build the two native desktop components with:

```sh
cargo build --manifest-path rust/Cargo.toml --release -p kaneo-api -p kaneo-desktop
```

The Linux AppImage is built through the Rust/Tauri shell. Install the matching
CLI once with `cargo install tauri-cli --version 2.11.4 --locked`, then run:

```sh
pnpm --filter @kaneo/desktop package:appimage
```

The package script sets `NO_STRIP=1` because the cached linuxdeploy binary
cannot strip the RELR sections used by current Arch Linux system libraries.

`kaneo-api` authenticates Better Auth session cookies and API keys directly
against the existing schema, serves board/project/task routes, publishes live
task events, and runs Codex through `kaneo-core`. `kaneo-desktop` starts that
API, serves the web bundle from a sibling `web/` directory when present, and
opens it in a native Tauri window. Set `KANEO_WEB_ROOT` when running the shell
from a development checkout.
