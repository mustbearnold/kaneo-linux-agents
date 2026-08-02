import type { AgentRun } from "./agent";

export type OrchestratorStatus =
  | "queued"
  | "running"
  | "waiting"
  | "failed"
  | "cancelled";

export type OrchestratorMessage = {
  id: string;
  role: "user" | "assistant" | "system";
  text: string;
  at: string;
};

export type OrchestratorChild = {
  id: string;
  taskId: string | null;
  prompt: string;
  cwd: string;
  model?: string;
  networkAccess: boolean;
  maxSeconds: number;
  attempt: number;
  maxRetries: number;
  runId: string;
  status: AgentRun["status"];
  error?: string;
  createdAt: string;
  updatedAt: string;
  run: AgentRun | null;
};

export type Orchestrator = {
  id: string;
  workspaceId: string;
  projectId: string;
  goal: string;
  cwd: string;
  model?: string;
  networkAccess: boolean;
  maxChildren: number;
  maxRetries: number;
  maxSeconds: number;
  status: OrchestratorStatus;
  createdAt: string;
  updatedAt: string;
  activeTurnId: string | null;
  error?: string;
  messages: OrchestratorMessage[];
  children: OrchestratorChild[];
};

export type CreateOrchestratorRequest = {
  projectId: string;
  goal: string;
  cwd?: string;
  model?: string;
  networkAccess?: boolean;
  maxChildren?: number;
  maxRetries?: number;
  maxSeconds?: number;
};
