import { build } from "esbuild";
import { cp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { builtinModules } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(desktopRoot, "../..");
const runtimeRoot = join(desktopRoot, "runtime");
const webDist = join(repoRoot, "apps/web/dist");
const drizzleDir = join(repoRoot, "apps/api/drizzle");
const apiSource = join(repoRoot, "apps/api/src/index.ts");

async function mustExist(path, label) {
  try {
    await stat(path);
  } catch {
    throw new Error(`${label} is missing at ${path}`);
  }
}

await mustExist(webDist, "The web build");
await mustExist(drizzleDir, "The API migrations");
await mustExist(apiSource, "The API source");

await rm(runtimeRoot, { recursive: true, force: true });
await mkdir(join(runtimeRoot, "api"), { recursive: true });

await cp(webDist, join(runtimeRoot, "web"), { recursive: true });
await cp(drizzleDir, join(runtimeRoot, "drizzle"), { recursive: true });

const nodeBuiltins = [
  ...builtinModules,
  ...builtinModules.map((name) => `node:${name}`),
];

await build({
  entryPoints: [apiSource],
  outfile: join(runtimeRoot, "api/index.cjs"),
  bundle: true,
  packages: "bundle",
  platform: "node",
  format: "cjs",
  external: nodeBuiltins,
  define: {
    "import.meta.url": "__kaneoImportMetaUrl",
  },
  banner: {
    js: 'const __kaneoImportMetaUrl = require("node:url").pathToFileURL(__filename).href;',
  },
  legalComments: "none",
  sourcemap: false,
  target: "node20",
});

const envSource = join(repoRoot, ".env");
try {
  const env = await readFile(envSource);
  await writeFile(join(runtimeRoot, "default.env"), env);
} catch {
  // A packaged app can still start with environment variables supplied by the
  // user. The default file is only for this local self-hosted installation.
}

console.log(`Desktop runtime prepared at ${runtimeRoot}`);
