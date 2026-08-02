type TauriInvoke = (
  command: string,
  args?: Record<string, unknown>,
) => Promise<unknown>;

type TauriWindow = Window & {
  __TAURI__?: {
    core?: {
      invoke?: TauriInvoke;
    };
  };
  __TAURI_INTERNALS__?: {
    invoke?: TauriInvoke;
  };
};

export async function pickProjectFolder(): Promise<string | null> {
  const tauriWindow = window as TauriWindow;
  const invoke =
    tauriWindow.__TAURI__?.core?.invoke ??
    tauriWindow.__TAURI_INTERNALS__?.invoke;

  if (!invoke) {
    throw new Error(
      "Folder picking is only available in the Kaneo desktop app.",
    );
  }

  const selected = await invoke("pick_project_folder");
  return typeof selected === "string" && selected.trim()
    ? selected.trim()
    : null;
}
