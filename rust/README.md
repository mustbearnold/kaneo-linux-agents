# Kaneo Rust migration

This workspace is the beginning of the full Kaneo migration into one Rust
project. It starts at the performance-sensitive boundary: agent process
supervision, bounded concurrency, cancellation, timeouts, event streaming, and
secret redaction.

The current TypeScript API remains the compatibility runtime while feature
parity is built in Rust. The intended end state is a Rust Kaneo core and API
shared by the desktop shell and web client, with no duplicate agent scheduler.

Run the first migration gate with:

```sh
cargo test --manifest-path rust/Cargo.toml
```

The `kaneo-core` crate is deliberately independent of a web framework and
database. That makes it possible to port the API and persistence layers in
separate slices without coupling the scheduler to HTTP or UI code.
