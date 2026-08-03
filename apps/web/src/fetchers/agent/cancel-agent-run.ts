import { client } from "@kaneo/libs";
import { AgentRequestError } from "@/fetchers/agent/agent-request-error";
import type { AgentRun } from "@/types/agent";

async function cancelAgentRun(id: string): Promise<AgentRun> {
  const response = await client.agent.runs[":id"].cancel.$post({
    param: { id },
  });
  if (!response.ok) {
    throw new AgentRequestError(response.status, await response.text());
  }
  return response.json() as Promise<AgentRun>;
}

export default cancelAgentRun;
