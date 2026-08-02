export type AgentRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

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
  events: Array<{
    at: string;
    type: string;
    text: string;
  }>;
};

export type StartAgentRunRequest = {
  projectId: string;
  prompt: string;
  cwd?: string;
  model?: string;
  networkAccess?: boolean;
  maxSeconds?: number;
};
