import { client } from "@kaneo/libs";
import { AgentRequestError } from "@/fetchers/agent/agent-request-error";
import type { AgentRun, StartAgentRunRequest } from "@/types/agent";

async function startAgentRun(input: StartAgentRunRequest): Promise<AgentRun> {
  const response = await client.agent.runs.$post({ json: input });
  if (!response.ok) {
    throw new AgentRequestError(response.status, await response.text());
  }
  return response.json() as Promise<AgentRun>;
}

export default startAgentRun;
