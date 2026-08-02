import { client } from "@kaneo/libs";
import type { AgentRun } from "@/types/agent";

async function getAgentRun(id: string): Promise<AgentRun> {
  const response = await client.agent.runs[":id"].$get({ param: { id } });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<AgentRun>;
}

export default getAgentRun;
