import { windowId } from "@kaneo/libs";
import { AgentRequestError } from "@/fetchers/agent/agent-request-error";
import { getApiUrl } from "@/fetchers/get-api-url";
import type {
  CreateOrchestratorRequest,
  Orchestrator,
} from "@/types/orchestrator";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(getApiUrl(path), {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "X-Kaneo-Window-Id": windowId,
      ...init?.headers,
    },
  });
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
  return response.json() as Promise<T>;
}

export function createOrchestrator(
  input: CreateOrchestratorRequest,
): Promise<Orchestrator> {
  return request<Orchestrator>("agent/orchestrators", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function listOrchestrators(projectId: string): Promise<Orchestrator[]> {
  const query = new URLSearchParams({ projectId });
  return request<Orchestrator[]>(`agent/orchestrators?${query.toString()}`);
}

export function getOrchestrator(id: string): Promise<Orchestrator> {
  return request<Orchestrator>(`agent/orchestrators/${encodeURIComponent(id)}`);
}

export function sendOrchestratorMessage(
  id: string,
  message: string,
): Promise<Orchestrator> {
  return request<Orchestrator>(
    `agent/orchestrators/${encodeURIComponent(id)}/messages`,
    {
      method: "POST",
      body: JSON.stringify({ message }),
    },
  );
}

export function cancelOrchestrator(id: string): Promise<Orchestrator> {
  return request<Orchestrator>(
    `agent/orchestrators/${encodeURIComponent(id)}/cancel`,
    {
      method: "POST",
    },
  );
}
