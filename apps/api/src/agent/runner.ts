import { type ChildProcess, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { access, mkdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";

export type AgentRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type AgentRunEvent = {
  at: string;
  type: string;
  text: string;
};

export type AgentRun = {
  id: string;
  workspaceId: string;
  projectId: string;
  prompt: string;
  cwd: string;
  model?: string;
  networkAccess: boolean;
  status: AgentRunStatus;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  exitCode: number | null;
  error?: string;
  events: AgentRunEvent[];
};

type StartAgentRunInput = {
  workspaceId: string;
  projectId: string;
  prompt: string;
  cwd?: string;
  projectCwd?: string;
  model?: string;
  networkAccess?: boolean;
  maxSeconds?: number;
  bearerToken: string;
};

type AgentProcess = {
  child: ChildProcess;
  timeout: NodeJS.Timeout;
};

const runs = new Map<string, AgentRun>();
const processes = new Map<string, AgentProcess>();
const MAX_ACTIVE_RUNS = 2;
const MAX_EVENTS = 1000;
const MAX_EVENT_TEXT = 12_000;
const DEFAULT_MAX_SECONDS = 60 * 60;

function redactSecrets(text: string): string {
  return text
    .replace(
      /(\\?["']?(?:token|access_token|refresh_token|api[_-]?key)\\?["']?\s*:\s*\\?["'])[^"\\]*(\\?["'])/gi,
      "$1[redacted]$2",
    )
    .replace(/(Bearer\s+)[^\s"']+/gi, "$1[redacted]");
}

function appendEvent(run: AgentRun, type: string, text: string) {
  run.events.push({
    at: new Date().toISOString(),
    type,
    text: redactSecrets(text).slice(0, MAX_EVENT_TEXT),
  });
  if (run.events.length > MAX_EVENTS) {
    run.events.splice(0, run.events.length - MAX_EVENTS);
  }
}

function eventText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function addJsonLine(run: AgentRun, line: string) {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    const type = typeof parsed.type === "string" ? parsed.type : "event";
    const item =
      parsed.item && typeof parsed.item === "object"
        ? (parsed.item as Record<string, unknown>)
        : undefined;
    const content = item?.content;
    const text =
      eventText(item?.text) ||
      eventText(item?.message) ||
      (Array.isArray(content) ? eventText(content) : "") ||
      eventText(parsed.message) ||
      eventText(parsed.error) ||
      trimmed;
    appendEvent(run, type, text);
  } catch {
    appendEvent(run, "output", trimmed);
  }
}

function buildPrompt(input: StartAgentRunInput): string {
  return [
    "You are the autonomous delivery agent for a Kaneo project.",
    `Kaneo workspace ID: ${input.workspaceId}`,
    `Kaneo project ID: ${input.projectId}`,
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
  ].join("\n");
}

async function resolveWorkingDirectory(
  input: StartAgentRunInput,
  runId: string,
) {
  const requested = input.cwd?.trim();
  const projectDefault = input.projectCwd?.trim();
  const selected = requested || projectDefault;
  if (selected && !isAbsolute(selected)) {
    throw new Error("The agent working directory must be an absolute path.");
  }

  const cwd = selected
    ? resolve(selected)
    : join(tmpdir(), "kaneo-agent-runs", runId);

  if (!selected) {
    await mkdir(cwd, { recursive: true });
  }

  const info = await stat(cwd).catch(() => null);
  if (!info?.isDirectory()) {
    throw new Error(`Agent working directory is not a directory: ${cwd}`);
  }

  const allowedRoot = process.env.KANEO_AGENT_ALLOWED_ROOT?.trim();
  if (allowedRoot) {
    const root = resolve(allowedRoot);
    const pathFromRoot = relative(root, cwd);
    if (pathFromRoot.startsWith("..") || isAbsolute(pathFromRoot)) {
      throw new Error(`Agent working directory must be inside ${root}.`);
    }
  }

  await access(cwd);
  return cwd;
}

function publicRun(run: AgentRun): AgentRun {
  return {
    ...run,
    events: [...run.events],
  };
}

export async function startAgentRun(
  input: StartAgentRunInput,
): Promise<AgentRun> {
  const activeCount = [...runs.values()].filter(
    (run) => run.status === "queued" || run.status === "running",
  ).length;
  if (activeCount >= MAX_ACTIVE_RUNS) {
    throw new Error(
      "Kaneo already has the maximum number of active agent runs.",
    );
  }

  const id = randomUUID();
  const cwd = await resolveWorkingDirectory(input, id);
  const run: AgentRun = {
    id,
    workspaceId: input.workspaceId,
    projectId: input.projectId,
    prompt: input.prompt.trim(),
    cwd,
    model: input.model?.trim() || undefined,
    networkAccess: input.networkAccess === true,
    status: "queued",
    createdAt: new Date().toISOString(),
    exitCode: null,
    events: [],
  };
  runs.set(id, run);

  const args = [
    "exec",
    "--json",
    "--ephemeral",
    "--sandbox",
    "workspace-write",
    "-C",
    cwd,
    "--skip-git-repo-check",
    "-c",
    'approval_policy="never"',
    "-c",
    'mcp_servers.kaneo.bearer_token_env_var="KANEO_AGENT_TOKEN"',
    "-c",
    'mcp_servers.kaneo.default_tools_approval_mode="approve"',
    "-c",
    'mcp_servers.kaneo.disabled_tools=["delete_project","delete_task","delete_task_comment","delete_label","delete_task_relation"]',
  ];
  if (run.networkAccess) {
    args.push("-c", "sandbox_workspace_write.network_access=true");
  }
  if (run.model) args.push("--model", run.model);
  args.push(buildPrompt(input));

  const childEnvironment: NodeJS.ProcessEnv = {
    ...process.env,
    KANEO_AGENT_TOKEN: input.bearerToken,
    CODEX_CI: "1",
  };
  delete childEnvironment.CODEX_PERMISSION_PROFILE;
  delete childEnvironment.CODEX_THREAD_ID;

  const child = spawn(process.env.KANEO_CODEX_BIN || "codex", args, {
    cwd,
    env: childEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const maxSeconds = Math.min(
    Math.max(input.maxSeconds ?? DEFAULT_MAX_SECONDS, 60),
    24 * 60 * 60,
  );
  const timeout = setTimeout(() => {
    if (!child.killed) {
      appendEvent(run, "timeout", `Agent run exceeded ${maxSeconds} seconds.`);
      run.error = "Agent run timed out.";
      child.kill("SIGTERM");
    }
  }, maxSeconds * 1000);

  run.status = "running";
  run.startedAt = new Date().toISOString();
  processes.set(id, { child, timeout });
  appendEvent(run, "run.started", `Codex started in ${cwd}.`);

  let stdoutBuffer = "";
  child.stdout?.on("data", (chunk: Buffer | string) => {
    stdoutBuffer += chunk.toString();
    const lines = stdoutBuffer.split(/\r?\n/);
    stdoutBuffer = lines.pop() ?? "";
    for (const line of lines) addJsonLine(run, line);
  });
  child.stderr?.on("data", (chunk: Buffer | string) => {
    const text = chunk.toString().trim();
    if (text) appendEvent(run, "stderr", text);
  });
  child.on("error", (error) => {
    run.status = "failed";
    run.error = error.message;
    appendEvent(run, "run.error", error.message);
  });
  child.on("close", (code, signal) => {
    if (stdoutBuffer.trim()) addJsonLine(run, stdoutBuffer);
    clearTimeout(timeout);
    processes.delete(id);
    run.exitCode = code;
    run.finishedAt = new Date().toISOString();
    if (run.status === "cancelled") {
      appendEvent(run, "run.cancelled", "Agent run cancelled.");
      return;
    }
    if (run.status === "failed" || code !== 0) {
      run.status = "failed";
      run.error ??= signal
        ? `Codex exited with signal ${signal}.`
        : `Codex exited with code ${code ?? "unknown"}.`;
      appendEvent(run, "run.failed", run.error);
      return;
    }
    run.status = "completed";
    appendEvent(run, "run.completed", "Agent run completed successfully.");
  });

  return publicRun(run);
}

export function getAgentRun(id: string): AgentRun | null {
  const run = runs.get(id);
  return run ? publicRun(run) : null;
}

export function listAgentRuns(
  workspaceId: string,
  projectId: string,
  limit = 20,
): AgentRun[] {
  const boundedLimit = Math.min(Math.max(limit, 1), 50);
  return [...runs.values()]
    .filter(
      (run) => run.workspaceId === workspaceId && run.projectId === projectId,
    )
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
    .slice(0, boundedLimit)
    .map(publicRun);
}

export function cancelAgentRun(id: string): AgentRun | null {
  const run = runs.get(id);
  const process = processes.get(id);
  if (!run || !process) return run ? publicRun(run) : null;
  run.status = "cancelled";
  run.finishedAt = new Date().toISOString();
  process.child.kill("SIGTERM");
  return publicRun(run);
}
