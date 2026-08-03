import { windowId } from "@kaneo/libs";
import { AgentRequestError } from "@/fetchers/agent/agent-request-error";
import { getApiUrl } from "@/fetchers/get-api-url";
import type { AgentRun } from "@/types/agent";

async function listAgentRuns(projectId: string): Promise<AgentRun[]> {
  const query = new URLSearchParams({ projectId });
  const response = await fetch(
    `${getApiUrl("agent/runs")}?${query.toString()}`,
    {
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-Kaneo-Window-Id": windowId,
      },
    },
  );
  if (!response.ok) {
    const body = await response.text();
    let message = body;
    try {
      message = (JSON.parse(body) as { message?: string }).message ?? body;
    } catch {
      // Keep the raw response when the API did not return JSON.
    }
    throw new AgentRequestError(
      response.status,
      message || `Request failed with HTTP ${response.status}`,
    );
  }
  return response.json() as Promise<AgentRun[]>;
}

export default listAgentRuns;
