import {
  Bot,
  CheckCircle2,
  CircleAlert,
  FolderOpen,
  LoaderCircle,
  MessageCircle,
  Send,
  ShieldCheck,
  Square,
  Users,
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
import {
  cancelOrchestrator,
  createOrchestrator,
  getOrchestrator,
  sendOrchestratorMessage,
} from "@/fetchers/agent/orchestrator";
import { toast } from "@/lib/toast";
import type {
  Orchestrator,
  OrchestratorChild,
  OrchestratorStatus,
} from "@/types/orchestrator";

type ProjectOrchestratorDialogProps = {
  projectId: string;
};

const DEFAULT_GOAL =
  "Coordinate the highest-priority actionable tasks in this project. Split independent work across child agents, have them implement and verify it, and keep the Kanban board accurate.";

function isActive(status?: OrchestratorStatus) {
  return status === "queued" || status === "running";
}

function statusLabel(status?: OrchestratorStatus) {
  switch (status) {
    case "queued":
      return "Queued";
    case "running":
      return "Working";
    case "waiting":
      return "Waiting for your message";
    case "failed":
      return "Failed";
    case "cancelled":
      return "Cancelled";
    default:
      return "Ready";
  }
}

function statusIcon(status?: OrchestratorStatus) {
  if (status === "queued" || status === "running") {
    return <LoaderCircle className="size-4 animate-spin text-primary" />;
  }
  if (status === "waiting") {
    return <CheckCircle2 className="size-4 text-emerald-500" />;
  }
  return <CircleAlert className="size-4 text-amber-500" />;
}

function nestedAgentCount(orchestrator: Orchestrator): number {
  return orchestrator.children.reduce(
    (total, child) =>
      total + 1 + (child.orchestrator ? nestedAgentCount(child.orchestrator) : 0),
    0,
  );
}

function OrchestratorChildren({
  children,
}: {
  children: OrchestratorChild[];
}) {
  return (
    <div className="space-y-1.5">
      {children.map((child) => {
        const nested = child.orchestrator;
        return (
          <div key={child.id} className="space-y-1.5">
            <div className="flex items-center justify-between gap-2 rounded-md bg-muted/55 px-2 py-1.5">
              <span className="flex min-w-0 items-center gap-1.5 truncate">
                <Bot className="size-3 shrink-0 text-primary" />
                <span className="truncate">
                  {child.taskId ?? child.id.slice(0, 8)}
                </span>
              </span>
              <span className="shrink-0 text-muted-foreground">
                {nested ? statusLabel(nested.status) : child.status}
                {child.attempt > 1 ? " · try " + child.attempt : ""}
              </span>
            </div>
            {nested && nested.children.length > 0 && (
              <div className="ml-4 border-l border-border pl-2">
                <OrchestratorChildren children={nested.children} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function ProjectOrchestratorDialog({
  projectId,
}: ProjectOrchestratorDialogProps) {
  const [open, setOpen] = useState(false);
  const [goal, setGoal] = useState(DEFAULT_GOAL);
  const [cwd, setCwd] = useState("");
  const [networkAccess, setNetworkAccess] = useState(false);
  const [maxChildren, setMaxChildren] = useState("4");
  const [message, setMessage] = useState("");
  const [orchestrator, setOrchestrator] = useState<Orchestrator | null>(null);
  const [isMonitorOpen, setIsMonitorOpen] = useState(false);
  const [isStarting, setIsStarting] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);

  const active = isActive(orchestrator?.status);

  useEffect(() => {
    if (!orchestrator?.id || !isActive(orchestrator.status)) return;
    const interval = window.setInterval(() => {
      void getOrchestrator(orchestrator.id)
        .then(setOrchestrator)
        .catch((error: unknown) => {
          toast.error(
            error instanceof Error
              ? error.message
              : "Couldn't read orchestrator status.",
          );
        });
    }, 1200);
    return () => window.clearInterval(interval);
  }, [orchestrator?.id, orchestrator?.status]);

  const messages = useMemo(
    () => orchestrator?.messages.slice(-24) ?? [],
    [orchestrator],
  );

  const handleStart = async () => {
    if (!goal.trim()) return;
    setIsStarting(true);
    try {
      const started = await createOrchestrator({
        projectId,
        goal: goal.trim(),
        ...(cwd.trim() ? { cwd: cwd.trim() } : {}),
        networkAccess,
        maxChildren: Math.max(1, Math.min(8, Number(maxChildren) || 4)),
        maxRetries: 1,
        maxSeconds: 60 * 60,
      });
      setOrchestrator(started);
      setOpen(false);
      setIsMonitorOpen(true);
      toast.success("Orchestrator started");
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : "Couldn't start the orchestrator.",
      );
    } finally {
      setIsStarting(false);
    }
  };

  const handleSend = async () => {
    if (!orchestrator || !message.trim()) return;
    setIsSending(true);
    try {
      const updated = await sendOrchestratorMessage(
        orchestrator.id,
        message.trim(),
      );
      setOrchestrator(updated);
      setMessage("");
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : "Couldn't send the orchestrator message.",
      );
    } finally {
      setIsSending(false);
    }
  };

  const handleCancel = async () => {
    if (!orchestrator) return;
    setIsCancelling(true);
    try {
      setOrchestrator(await cancelOrchestrator(orchestrator.id));
      toast.success("Orchestrator cancelled");
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : "Couldn't cancel the orchestrator.",
      );
    } finally {
      setIsCancelling(false);
    }
  };

  return (
    <>
      <Button
        variant="outline"
        size="xs"
        className="gap-1.5"
        onClick={() => {
          if (orchestrator) {
            setIsMonitorOpen(true);
          } else {
            setOpen(true);
          }
        }}
        title="Chat with an orchestrator that delegates work to child agents"
      >
        <Users className="size-3.5" />
        <span className="hidden sm:inline">
          {active ? "Orchestrator live" : "Orchestrate"}
        </span>
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-2xl" bottomStickOnMobile={false}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Users className="size-5" />
              Start project orchestrator
            </DialogTitle>
            <DialogDescription>
              A parent Codex agent will split the goal into a live nested agent
              tree and keep the Kanban tasks coordinated.
            </DialogDescription>
          </DialogHeader>

          <DialogPanel className="space-y-4">
            <label htmlFor="orchestrator-goal" className="block space-y-1.5">
              <span className="text-sm font-medium">Goal</span>
              <Textarea
                id="orchestrator-goal"
                value={goal}
                onChange={(event) => setGoal(event.target.value)}
                disabled={isStarting}
                className="min-h-28"
                placeholder="What should the team of agents deliver?"
              />
            </label>

            <label htmlFor="orchestrator-cwd" className="block space-y-1.5">
              <span className="flex items-center gap-1.5 text-sm font-medium">
                <FolderOpen className="size-3.5" />
                Shared working directory{" "}
                <span className="font-normal text-muted-foreground">
                  (optional)
                </span>
              </span>
              <Input
                id="orchestrator-cwd"
                value={cwd}
                onChange={(event) => setCwd(event.target.value)}
                disabled={isStarting}
                placeholder="/home/you/Projects/your-repository"
              />
            </label>

            <label htmlFor="orchestrator-children" className="block space-y-1.5">
              <span className="text-sm font-medium">Maximum child agents</span>
              <Input
                id="orchestrator-children"
                inputMode="numeric"
                value={maxChildren}
                onChange={(event) => setMaxChildren(event.target.value)}
                disabled={isStarting}
              />
            </label>

            <div className="flex items-start justify-between gap-4 rounded-lg border border-border bg-muted/35 p-3">
              <div className="flex gap-2.5">
                <ShieldCheck className="mt-0.5 size-4 shrink-0 text-primary" />
                <div className="space-y-1">
                  <p className="text-sm font-medium">Allow network access</p>
                  <p className="text-xs text-muted-foreground">
                    Off by default; enable it when child agents need package
                    downloads or external services.
                  </p>
                </div>
              </div>
              <Switch
                checked={networkAccess}
                onCheckedChange={setNetworkAccess}
                disabled={isStarting}
                aria-label="Allow network access"
              />
            </div>
          </DialogPanel>

          <DialogFooter>
            <Button
              onClick={() => void handleStart()}
              disabled={isStarting || !goal.trim()}
              loading={isStarting}
            >
              <Bot className="size-3.5" />
              Start orchestrator
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {isMonitorOpen && orchestrator && (
        <div className="pointer-events-auto fixed inset-x-3 bottom-3 z-40 sm:top-14 sm:right-4 sm:bottom-auto sm:left-auto sm:w-[min(38rem,calc(100vw-2rem))]">
          <div className="rounded-xl border border-border bg-popover text-popover-foreground shadow-xl/10">
            <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
              <div className="flex min-w-0 items-start gap-2">
                {statusIcon(orchestrator.status)}
                <div className="min-w-0">
                  <p className="text-sm font-medium">
                    Orchestrator {statusLabel(orchestrator.status).toLowerCase()}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    The Kanban board stays live while child agents work.
                  </p>
                </div>
              </div>
              <Button
                aria-label="Close orchestrator monitor"
                className="-mr-1 -mt-1 shrink-0"
                onClick={() => setIsMonitorOpen(false)}
                size="icon"
                variant="ghost"
              >
                <X className="size-4" />
              </Button>
            </div>

            <div className="space-y-3 p-3">
              <div className="max-h-56 space-y-2 overflow-y-auto rounded-md bg-muted/50 p-3 text-xs">
                {messages.length === 0 ? (
                  <span className="text-muted-foreground">
                    Waiting for the orchestrator…
                  </span>
                ) : (
                  messages.map((item) => (
                    <div key={item.id} className="space-y-0.5">
                      <span className="font-medium text-primary">
                        {item.role === "assistant" ? "Orchestrator" : item.role}
                      </span>
                      <p className="whitespace-pre-wrap text-foreground/85">
                        {item.text}
                      </p>
                    </div>
                  ))
                )}
              </div>

              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Users className="size-3.5" />
                  {nestedAgentCount(orchestrator)} agents in tree
                </span>
                <span>{statusLabel(orchestrator.status)}</span>
              </div>

              {orchestrator.children.length > 0 && (
                <div className="max-h-32 space-y-1 overflow-y-auto rounded-md border border-border p-2 text-xs">
                  <OrchestratorChildren children={orchestrator.children} />
                </div>
              )}

              {orchestrator.error && (
                <p className="text-xs text-destructive">{orchestrator.error}</p>
              )}

              {orchestrator.status === "waiting" && (
                <div className="flex items-end gap-2">
                  <label className="min-w-0 flex-1 space-y-1">
                    <span className="sr-only">Message orchestrator</span>
                    <Textarea
                      value={message}
                      onChange={(event) => setMessage(event.target.value)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" && !event.shiftKey) {
                          event.preventDefault();
                          void handleSend();
                        }
                      }}
                      className="min-h-16"
                      placeholder="Ask the orchestrator what to do next…"
                      disabled={isSending}
                    />
                  </label>
                  <Button
                    size="icon"
                    onClick={() => void handleSend()}
                    disabled={isSending || !message.trim()}
                    loading={isSending}
                    aria-label="Send message to orchestrator"
                  >
                    <Send className="size-4" />
                  </Button>
                </div>
              )}

              <div className="flex justify-end gap-2">
                {active && (
                  <Button
                    size="xs"
                    variant="destructive-outline"
                    onClick={() => void handleCancel()}
                    disabled={isCancelling}
                    loading={isCancelling}
                  >
                    <Square className="size-3.5" />
                    Stop all agents
                  </Button>
                )}
                {!active && orchestrator.status !== "cancelled" && (
                  <Button size="xs" onClick={() => setOpen(true)}>
                    <MessageCircle className="size-3.5" />
                    Start another
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
