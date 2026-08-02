import { app, BrowserWindow, dialog, shell } from "electron";
import { createServer, request } from "node:http";
import { createReadStream, existsSync, readFileSync, statSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const desktopRoot = dirname(fileURLToPath(import.meta.url));
const apiPort = 1337;
const webPort = 5173;
const apiOrigin = `http://127.0.0.1:${apiPort}`;
const webOrigin = `http://127.0.0.1:${webPort}`;

let apiProcess;
let webServer;
let mainWindow;

function runtimeRoot() {
  const appRuntime = join(app.getAppPath(), "runtime");
  return existsSync(appRuntime)
    ? appRuntime
    : join(process.resourcesPath, "runtime");
}

function parseEnv(contents) {
  const values = {};
  for (const line of contents.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator < 1) continue;
    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    values[key] = value;
  }
  return values;
}

async function loadEnvironment() {
  const root = runtimeRoot();
  const userDataEnv = join(app.getPath("userData"), ".env");
  const candidates = app.isPackaged
    ? [userDataEnv, join(root, "default.env")]
    : [join(desktopRoot, "../../.env")];
  let values = {};

  for (const candidate of candidates) {
    try {
      values = parseEnv(await readFile(candidate, "utf8"));
      if (app.isPackaged && candidate !== userDataEnv) {
        await mkdir(app.getPath("userData"), { recursive: true });
        try {
          await writeFile(userDataEnv, await readFile(candidate), { flag: "wx" });
        } catch {
          // Another launch may have created it first.
        }
      }
      break;
    } catch {
      // Try the next configuration source.
    }
  }

  return {
    ...process.env,
    ...values,
    NODE_ENV: "production",
    KANEO_API_URL: apiOrigin,
    KANEO_CLIENT_URL: webOrigin,
    CORS_ORIGINS: webOrigin,
    AUTH_SECRET:
      values.AUTH_SECRET || process.env.AUTH_SECRET || randomBytes(32).toString("hex"),
  };
}

function getStatus(url) {
  return new Promise((resolveStatus) => {
    const client = request(url, { method: "GET" }, (response) => {
      response.resume();
      resolveStatus(response.statusCode ?? 0);
    });
    client.setTimeout(750, () => {
      client.destroy();
      resolveStatus(0);
    });
    client.on("error", () => resolveStatus(0));
    client.end();
  });
}

async function waitFor(url, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((await getStatus(url)) === 200) return true;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  return false;
}

function mimeType(path) {
  return (
    {
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".json": "application/json; charset=utf-8",
      ".svg": "image/svg+xml",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".webp": "image/webp",
      ".woff": "font/woff",
      ".woff2": "font/woff2",
    }[extname(path).toLowerCase()] || "application/octet-stream"
  );
}

function startWebServer(webRoot) {
  const root = resolve(webRoot);
  const fallback = join(root, "index.html");
  webServer = createServer((incoming, response) => {
    try {
      const pathname = decodeURIComponent(
        new URL(incoming.url || "/", webOrigin).pathname,
      );
      const candidate = resolve(root, `.${pathname}`);
      const relativePath = relative(root, candidate);
      const safe = relativePath && !relativePath.startsWith("..") && !relativePath.startsWith("/");
      const target = safe && existsSync(candidate) && !statSync(candidate).isDirectory()
        ? candidate
        : fallback;
      response.writeHead(200, { "Content-Type": mimeType(target) });
      createReadStream(target).pipe(response);
    } catch {
      response.writeHead(404);
      response.end("Not found");
    }
  });

  webServer.listen(webPort, "127.0.0.1");
  return webServer;
}

function startApiServer(apiEntry, environment) {
  const command = app.isPackaged
    ? process.execPath
    : process.env.KANEO_NODE_PATH || "node";
  const childEnvironment = { ...environment };
  if (app.isPackaged) childEnvironment.ELECTRON_RUN_AS_NODE = "1";

  apiProcess = spawn(command, [apiEntry], {
    cwd: dirname(apiEntry),
    env: childEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  apiProcess.stdout.on("data", (chunk) => console.log(`[kaneo-api] ${chunk}`));
  apiProcess.stderr.on("data", (chunk) => console.error(`[kaneo-api] ${chunk}`));
  apiProcess.on("exit", (code, signal) => {
    if (!app.isQuitting && code !== 0) {
      console.error(`Kaneo API exited with code ${code ?? "?"} (${signal ?? "no signal"})`);
    }
  });
  return apiProcess;
}

async function ensureServices(environment) {
  const root = runtimeRoot();
  const apiEntry = join(root, "api/index.cjs");
  const webRoot = join(root, "web");

  if (!(await waitFor(`${apiOrigin}/api/health`, 1000))) {
    if (!existsSync(apiEntry)) {
      throw new Error(`The bundled API is missing at ${apiEntry}. Run the desktop runtime build first.`);
    }
    startApiServer(apiEntry, environment);
    if (!(await waitFor(`${apiOrigin}/api/health`))) {
      throw new Error("Kaneo's API did not become healthy. Check the PostgreSQL connection.");
    }
  }

  if (!(await waitFor(webOrigin, 1000))) {
    if (!existsSync(join(webRoot, "index.html"))) {
      throw new Error(`The bundled web app is missing at ${webRoot}. Run the desktop runtime build first.`);
    }
    startWebServer(webRoot);
    if (!(await waitFor(webOrigin))) {
      throw new Error("Kaneo's desktop web server did not start.");
    }
  }
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 960,
    minWidth: 960,
    minHeight: 640,
    title: "Kaneo",
    webPreferences: {
      contextIsolation: true,
      sandbox: true,
      preload: join(desktopRoot, "preload.mjs"),
    },
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//.test(url) && !url.startsWith(webOrigin)) {
      void shell.openExternal(url);
    }
    return { action: "deny" };
  });
  void mainWindow.loadURL(webOrigin);
}

app.whenReady().then(async () => {
  try {
    const environment = await loadEnvironment();
    await ensureServices(environment);
    createMainWindow();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    dialog.showErrorBox("Kaneo could not start", message);
    app.quit();
  }
});

app.on("before-quit", () => {
  app.isQuitting = true;
  if (apiProcess && !apiProcess.killed) apiProcess.kill("SIGTERM");
  if (webServer) webServer.close();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
