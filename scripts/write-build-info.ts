import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distDir = path.join(rootDir, "dist");
const pkgPath = path.join(rootDir, "package.json");

const readPackageVersion = () => {
  try {
    const raw = fs.readFileSync(pkgPath, "utf8");
    const parsed = JSON.parse(raw) as { version?: string };
    return parsed.version ?? null;
  } catch {
    return null;
  }
};

const resolveCommit = () => {
  const envCommit = process.env.GIT_COMMIT?.trim() || process.env.GIT_SHA?.trim();
  if (envCommit) {
    return envCommit;
  }
  try {
    return execSync("git rev-parse HEAD", {
      cwd: rootDir,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
  } catch {
    return null;
  }
};

// Stamp the first-party signing trust root only when a release build supplies
// it; normal/dev/CI builds omit it so the runtime falls back to the all-zeros
// placeholder (signing stays dormant). A malformed value is skipped, never
// fatal — a bad env var must not break the build.
const resolveFirstPartyFingerprint = () => {
  const raw = process.env.OPENCLAW_FIRST_PARTY_FINGERPRINT?.trim().toLowerCase();
  if (!raw) {
    return null;
  }
  if (!/^[0-9a-f]{32}$/.test(raw)) {
    console.warn(
      "[build-info] ignoring malformed OPENCLAW_FIRST_PARTY_FINGERPRINT (expected 32 hex chars)",
    );
    return null;
  }
  return raw;
};

const version = readPackageVersion();
const commit = resolveCommit();
const firstPartyFingerprint = resolveFirstPartyFingerprint();

const buildInfo = {
  version,
  commit,
  builtAt: new Date().toISOString(),
  ...(firstPartyFingerprint ? { firstPartyFingerprint } : {}),
};

fs.mkdirSync(distDir, { recursive: true });
fs.writeFileSync(path.join(distDir, "build-info.json"), `${JSON.stringify(buildInfo, null, 2)}\n`);
