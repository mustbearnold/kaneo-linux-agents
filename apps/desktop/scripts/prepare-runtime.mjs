import {
  chmod,
  cp,
  mkdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(desktopRoot, "../..");
const runtimeRoot = join(desktopRoot, "runtime");
const webDist = join(repoRoot, "apps/web/dist");
const drizzleDir = join(repoRoot, "apps/api/drizzle");
const rustApiSource = join(repoRoot, "rust/target/release/kaneo-api");
const rustDesktopSource = join(repoRoot, "rust/target/release/kaneo-desktop");

async function mustExist(path, label) {
  try {
    await stat(path);
  } catch {
    throw new Error(`${label} is missing at ${path}`);
  }
}

await mustExist(webDist, "The web build");
await mustExist(drizzleDir, "The API migrations");

await rm(runtimeRoot, { recursive: true, force: true });

await cp(webDist, join(runtimeRoot, "web"), { recursive: true });
await cp(drizzleDir, join(runtimeRoot, "drizzle"), { recursive: true });

try {
  await stat(rustApiSource);
  const rustRuntimeDir = join(runtimeRoot, "rust");
  await mkdir(rustRuntimeDir, { recursive: true });
  const rustApiTarget = join(rustRuntimeDir, "kaneo-api");
  await cp(rustApiSource, rustApiTarget);
  await chmod(rustApiTarget, 0o755);
  console.log(`Rust API runtime copied to ${rustApiTarget}`);
  try {
    await stat(rustDesktopSource);
    const rustDesktopTarget = join(rustRuntimeDir, "kaneo-desktop");
    await cp(rustDesktopSource, rustDesktopTarget);
    await chmod(rustDesktopTarget, 0o755);
    console.log(`Rust desktop runtime copied to ${rustDesktopTarget}`);
  } catch {
    console.warn(
      `Rust desktop binary not found at ${rustDesktopSource}; the Rust API runtime is still available.`,
    );
  }
} catch {
  throw new Error(
    `Rust API binary not found at ${rustApiSource}; build the Rust runtime before packaging.`,
  );
}

const envSource = join(repoRoot, ".env");
try {
  const env = await readFile(envSource);
  await writeFile(join(runtimeRoot, "default.env"), env);
} catch {
  // A packaged app can still start with environment variables supplied by the
  // user. The default file is only for this local self-hosted installation.
}

console.log(`Desktop runtime prepared at ${runtimeRoot}`);
