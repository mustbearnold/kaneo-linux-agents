export class AgentRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "AgentRequestError";
    this.status = status;
  }
}

export function isAgentNotFound(error: unknown): boolean {
  return error instanceof AgentRequestError && error.status === 404;
}
