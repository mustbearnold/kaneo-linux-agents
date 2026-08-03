import { and, eq } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { describeRoute, resolver, validator } from "hono-openapi";
import * as v from "valibot";
import db from "../database";
import { projectTable } from "../database/schema";
import { requireWorkspacePermission } from "../utils/require-workspace-permission";
import { validateWorkspaceAccess } from "../utils/validate-workspace-access";
import { workspaceAccess } from "../utils/workspace-access-middleware";
import {
  cancelAgentRun,
  getAgentRun,
  listAgentRuns,
  startAgentRun,
} from "./runner";

const agentRunSchema = v.object({
  id: v.string(),
  workspaceId: v.string(),
  projectId: v.string(),
  prompt: v.string(),
  cwd: v.string(),
  model: v.optional(v.string()),
  networkAccess: v.boolean(),
  status: v.picklist(["queued", "running", "completed", "failed", "cancelled"]),
  createdAt: v.string(),
  startedAt: v.optional(v.string()),
  finishedAt: v.optional(v.string()),
  exitCode: v.nullable(v.number()),
  error: v.optional(v.string()),
  events: v.array(
    v.object({
      at: v.string(),
      type: v.string(),
      text: v.string(),
    }),
  ),
});

type AgentVariables = {
  userId: string;
  session: { token?: string } | null;
  workspaceId: string;
  apiKey?: { id: string };
};

type AgentContext = Context<{ Variables: AgentVariables }>;

async function authorizeAgentRun(
  c: AgentContext,
  run: { workspaceId: string },
  permissions: Record<string, string[]>,
) {
  await validateWorkspaceAccess(
    c.get("userId"),
    run.workspaceId,
    c.get("apiKey")?.id,
  );
  c.set("workspaceId", run.workspaceId);
  await requireWorkspacePermission(permissions)(c, async () => undefined);
}

const agent = new Hono<{ Variables: AgentVariables }>()
  .post(
    "/runs",
    describeRoute({
      operationId: "startAgentRun",
      tags: ["Agents"],
      description: "Start a bounded autonomous Codex run for a Kaneo project",
      responses: {
        202: {
          description: "Agent run started",
          content: { "application/json": { schema: resolver(agentRunSchema) } },
        },
      },
    }),
    validator(
      "json",
      v.object({
        projectId: v.pipe(v.string(), v.minLength(1)),
        prompt: v.pipe(v.string(), v.minLength(1), v.maxLength(20_000)),
        cwd: v.optional(v.pipe(v.string(), v.maxLength(1_000))),
        model: v.optional(v.pipe(v.string(), v.maxLength(120))),
        networkAccess: v.optional(v.boolean()),
        maxSeconds: v.optional(v.pipe(v.number(), v.integer(), v.minValue(60))),
      }),
    ),
    workspaceAccess.fromProject("projectId"),
    requireWorkspacePermission({
      project: ["read"],
      task: ["create", "update"],
    }),
    async (c) => {
      const input = c.req.valid("json");
      const session = c.get("session");
      const authorization = c.req.header("Authorization");
      const bearer = authorization?.match(/^Bearer\s+(\S+)$/i)?.[1];
      const token = bearer || session?.token;
      if (!token) {
        throw new HTTPException(401, {
          message: "An authenticated session token is required for agent runs.",
        });
      }

      const project = await db.query.projectTable.findFirst({
        where: and(
          eq(projectTable.id, input.projectId),
          eq(projectTable.workspaceId, c.get("workspaceId")),
        ),
        columns: { localPath: true },
      });
      if (!project) {
        throw new HTTPException(404, { message: "Project not found" });
      }

      try {
        const run = await startAgentRun({
          ...input,
          projectCwd: project.localPath ?? undefined,
          workspaceId: c.get("workspaceId"),
          bearerToken: token,
        });
        return c.json(run, 202);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new HTTPException(
          message.includes("maximum number") ? 409 : 400,
          { message },
        );
      }
    },
  )
  .get(
    "/runs",
    describeRoute({
      operationId: "listAgentRuns",
      tags: ["Agents"],
      description: "List recent direct agent runs for a Kaneo project",
      responses: {
        200: {
          description: "Recent direct agent runs",
          content: {
            "application/json": { schema: resolver(v.array(agentRunSchema)) },
          },
        },
      },
    }),
    validator(
      "query",
      v.object({
        projectId: v.pipe(v.string(), v.minLength(1)),
        limit: v.optional(
          v.pipe(
            v.string(),
            v.transform(Number),
            v.number(),
            v.integer("Limit must be an integer"),
            v.minValue(1, "Limit must be at least 1"),
            v.maxValue(50, "Limit must not exceed 50"),
          ),
          20,
        ),
      }),
    ),
    workspaceAccess.fromProject("projectId"),
    requireWorkspacePermission({ project: ["read"] }),
    (c) => {
      const { projectId, limit } = c.req.valid("query");
      return c.json(listAgentRuns(c.get("workspaceId"), projectId, limit));
    },
  )
  .get(
    "/runs/:id",
    describeRoute({
      operationId: "getAgentRun",
      tags: ["Agents"],
      description: "Get the current status and events for an agent run",
      responses: {
        200: {
          description: "Agent run status",
          content: { "application/json": { schema: resolver(agentRunSchema) } },
        },
      },
    }),
    validator("param", v.object({ id: v.string() })),
    async (c) => {
      const run = getAgentRun(c.req.valid("param").id);
      if (!run)
        throw new HTTPException(404, { message: "Agent run not found" });
      await authorizeAgentRun(c, run, { project: ["read"] });
      return c.json(run);
    },
  )
  .post(
    "/runs/:id/cancel",
    describeRoute({
      operationId: "cancelAgentRun",
      tags: ["Agents"],
      description: "Cancel a running agent run",
      responses: {
        200: {
          description: "Agent run cancelled",
          content: { "application/json": { schema: resolver(agentRunSchema) } },
        },
      },
    }),
    validator("param", v.object({ id: v.string() })),
    async (c) => {
      const run = getAgentRun(c.req.valid("param").id);
      if (!run)
        throw new HTTPException(404, { message: "Agent run not found" });
      await authorizeAgentRun(c, run, {
        project: ["read"],
        task: ["update"],
      });
      const cancelled = cancelAgentRun(run.id);
      return c.json(cancelled ?? run);
    },
  );

export default agent;
