import {
  Bot,
  CheckCircle2,
  CircleAlert,
  FolderOpen,
  LoaderCircle,
  Play,
  ShieldCheck,
  Square,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogPanel,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import cancelAgentRun from "@/fetchers/agent/cancel-agent-run";
import getAgentRun from "@/fetchers/agent/get-agent-run";
import startAgentRun from "@/fetchers/agent/start-agent-run";
import { toast } from "@/lib/toast";
import type { AgentRun } from "@/types/agent";

type ProjectAgentDialogProps = {
  projectId: string;
};

const DEFAULT_PROMPT =
  "Work through the highest-priority actionable tasks in this project. Implement the next useful slice, verify it, and keep the task statuses and comments up to date.";

function isActive(status?: AgentRun["status"]) {
  return status === "queued" || status === "running";
}

function statusLabel(status?: AgentRun["status"]) {
  switch (status) {
    case "queued":
      return "Queued";
    case "running":
      return "Running";
    case "completed":
      return "Completed";
    case "failed":
      return "Failed";
    case "cancelled":
      return "Cancelled";
    default:
      return "Ready";
  }
}

export default function ProjectAgentDialog({
  projectId,
}: ProjectAgentDialogProps) {
  const [open, setOpen] = useState(false);
  const [prompt, setPrompt] = useState(DEFAULT_PROMPT);
  const [cwd, setCwd] = useState("");
  const [networkAccess, setNetworkAccess] = useState(false);
  const [run, setRun] = useState<AgentRun | null>(null);
  const [isMonitorOpen, setIsMonitorOpen] = useState(false);
  const [isStarting, setIsStarting] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);
  const activeRunId = run?.id;
  const activeRunStatus = run?.status;

  useEffect(() => {
    if (!activeRunId || !isActive(activeRunStatus)) return;

    const interval = window.setInterval(() => {
      void getAgentRun(activeRunId)
        .then(setRun)
        .catch((error: unknown) => {
          toast.error(
            error instanceof Error
              ? error.message
              : "Couldn't read agent status.",
          );
        });
    }, 1500);

    return () => window.clearInterval(interval);
  }, [activeRunId, activeRunStatus]);

  const visibleEvents = useMemo(() => run?.events.slice(-32) ?? [], [run]);
  const active = isActive(run?.status);

  const handleStart = async () => {
    if (!prompt.trim()) return;
    setIsStarting(true);
    try {
      const started = await startAgentRun({
        projectId,
        prompt,
        ...(cwd.trim() ? { cwd: cwd.trim() } : {}),
        networkAccess,
        maxSeconds: 60 * 60,
      });
      setRun(started);
      setOpen(false);
      setIsMonitorOpen(true);
      toast.success("Agent run started");
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Couldn't start the agent.",
      );
    } finally {
      setIsStarting(false);
    }
  };

  const handleCancel = async () => {
    if (!run) return;
    setIsCancelling(true);
    try {
      setRun(await cancelAgentRun(run.id));
      toast.success("Agent run cancelled");
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Couldn't cancel the agent.",
      );
    } finally {
      setIsCancelling(false);
    }
  };

  const handleOpenChange = (nextOpen: boolean) => {
    if (!nextOpen && active) return;
    setOpen(nextOpen);
  };

  return (
    <>
      <Button
        variant="outline"
        size="xs"
        className="gap-1.5"
        onClick={() => {
          if (active) {
            setIsMonitorOpen(true);
          } else {
            setIsMonitorOpen(false);
            setOpen(true);
          }
        }}
        title={
          active
            ? "Show the live agent run and keep watching the board"
            : "Run an autonomous Codex agent for this project"
        }
      >
        <Bot className="size-3.5" />
        <span className="hidden sm:inline">
          {active ? "Agent live" : "Run agent"}
        </span>
      </Button>

      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent className="max-w-2xl" bottomStickOnMobile={false}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Bot className="size-5" />
              Run agent for this project
            </DialogTitle>
            <DialogDescription>
              Codex will use Kaneo to inspect tasks, make progress, and report
              evidence back into the project.
            </DialogDescription>
          </DialogHeader>

          <DialogPanel className="space-y-4">
            <label htmlFor="agent-goal" className="block space-y-1.5">
              <span className="text-sm font-medium">Goal</span>
              <Textarea
                id="agent-goal"
                value={prompt}
                onChange={(event) => setPrompt(event.target.value)}
                disabled={active || isStarting}
                className="min-h-28"
                placeholder="Tell the agent what outcome to deliver..."
              />
            </label>

            <label htmlFor="agent-cwd" className="block space-y-1.5">
              <span className="flex items-center gap-1.5 text-sm font-medium">
                <FolderOpen className="size-3.5" />
                Local working directory{" "}
                <span className="font-normal text-muted-foreground">
                  (optional)
                </span>
              </span>
              <Input
                id="agent-cwd"
                value={cwd}
                onChange={(event) => setCwd(event.target.value)}
                disabled={active || isStarting}
                placeholder="/home/you/Projects/your-repository"
              />
              <span className="block text-xs text-muted-foreground">
                Leave blank for an isolated temporary directory when the work is
                only in Kaneo.
              </span>
            </label>

            <div className="flex items-start justify-between gap-4 rounded-lg border border-border bg-muted/35 p-3">
              <div className="flex gap-2.5">
                <ShieldCheck className="mt-0.5 size-4 shrink-0 text-primary" />
                <div className="space-y-1">
                  <p className="text-sm font-medium">Allow network access</p>
                  <p className="text-xs text-muted-foreground">
                    Off by default. Turn it on only when the project needs
                    package downloads or external services.
                  </p>
                </div>
              </div>
              <Switch
                checked={networkAccess}
                onCheckedChange={setNetworkAccess}
                disabled={active || isStarting}
                aria-label="Allow network access"
              />
            </div>

            {run && (
              <div className="space-y-3 rounded-lg border border-border bg-background p-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-sm font-medium">
                    {run.status === "running" || run.status === "queued" ? (
                      <LoaderCircle className="size-4 animate-spin text-primary" />
                    ) : run.status === "completed" ? (
                      <CheckCircle2 className="size-4 text-emerald-500" />
                    ) : (
                      <CircleAlert className="size-4 text-amber-500" />
                    )}
                    {statusLabel(run.status)}
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {run.cwd}
                  </span>
                </div>
                <div className="max-h-56 overflow-y-auto rounded-md bg-muted/50 p-2 font-mono text-[11px] leading-relaxed">
                  {visibleEvents.length === 0 ? (
                    <span className="text-muted-foreground">
                      Waiting for Codex output…
                    </span>
                  ) : (
                    visibleEvents.map((event) => (
                      <div
                        key={`${event.at}-${event.type}-${event.text}`}
                        className="mb-2 last:mb-0"
                      >
                        <span className="text-primary">{event.type}</span>
                        <span className="whitespace-pre-wrap text-foreground/80">
                          {" "}
                          {event.text}
                        </span>
                      </div>
                    ))
                  )}
                </div>
                {run.error && (
                  <p className="text-xs text-destructive">{run.error}</p>
                )}
              </div>
            )}
          </DialogPanel>

          <DialogFooter>
            {active ? (
              <Button
                variant="destructive-outline"
                onClick={() => void handleCancel()}
                disabled={isCancelling}
                loading={isCancelling}
              >
                <Square className="size-3.5" />
                Stop agent
              </Button>
            ) : (
              <Button
                onClick={() => void handleStart()}
                disabled={isStarting || !prompt.trim()}
                loading={isStarting}
              >
                <Play className="size-3.5" />
                {run ? "Run again" : "Start autonomous run"}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {isMonitorOpen && run && (
        <div className="pointer-events-auto fixed inset-x-3 bottom-3 z-40 sm:top-14 sm:right-4 sm:bottom-auto sm:left-auto sm:w-[min(32rem,calc(100vw-2rem))]">
          <div className="rounded-xl border border-border bg-popover text-popover-foreground shadow-xl/10">
            <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
              <div className="flex min-w-0 items-start gap-2">
                {active ? (
                  <LoaderCircle className="mt-0.5 size-4 shrink-0 animate-spin text-primary" />
                ) : run.status === "completed" ? (
                  <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-500" />
                ) : (
                  <CircleAlert className="mt-0.5 size-4 shrink-0 text-amber-500" />
                )}
                <div className="min-w-0">
                  <p className="text-sm font-medium">
                    {active
                      ? "Agent is working"
                      : `Agent ${statusLabel(run.status).toLowerCase()}`}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    The kanban board stays live while this monitor is open.
                  </p>
                </div>
              </div>
              <Button
                aria-label="Close agent monitor"
                className="-mr-1 -mt-1 shrink-0"
                onClick={() => setIsMonitorOpen(false)}
                size="icon"
                variant="ghost"
              >
                <X className="size-4" />
              </Button>
            </div>

            <div className="space-y-3 p-3">
              <div className="flex items-center justify-between gap-3 text-xs text-muted-foreground">
                <span>{statusLabel(run.status)}</span>
                <span
                  className="max-w-[70%] truncate font-mono"
                  title={run.cwd}
                >
                  {run.cwd}
                </span>
              </div>
              <div className="max-h-64 overflow-y-auto rounded-md bg-muted/50 p-2 font-mono text-[11px] leading-relaxed">
                {visibleEvents.length === 0 ? (
                  <span className="text-muted-foreground">
                    Waiting for Codex output…
                  </span>
                ) : (
                  visibleEvents.map((event) => (
                    <div
                      key={`${event.at}-${event.type}-${event.text}`}
                      className="mb-2 last:mb-0"
                    >
                      <span className="text-primary">{event.type}</span>
                      <span className="whitespace-pre-wrap text-foreground/80">
                        {" "}
                        {event.text}
                      </span>
                    </div>
                  ))
                )}
              </div>
              {run.error && (
                <p className="text-xs text-destructive">{run.error}</p>
              )}
              <div className="flex justify-end gap-2">
                {active ? (
                  <Button
                    size="xs"
                    variant="destructive-outline"
                    onClick={() => void handleCancel()}
                    disabled={isCancelling}
                    loading={isCancelling}
                  >
                    <Square className="size-3.5" />
                    Stop agent
                  </Button>
                ) : (
                  <Button
                    size="xs"
                    onClick={() => {
                      setIsMonitorOpen(false);
                      setOpen(true);
                    }}
                  >
                    <Play className="size-3.5" />
                    Run again
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
