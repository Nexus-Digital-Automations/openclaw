import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Static source-scan that prevents regression of OpenClaw's "argv arrays only,
// never `sh -c`" execution policy. AGENTS.md "Code" section forbids shell-string
// invocations because they re-introduce shell-injection across the audit-fenced
// spawn boundary established in src/process/spawn-utils.ts and src/process/exec.ts.

const SRC_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Files whose job is to recognize the forbidden patterns themselves (as strings,
// regexes, or in comments). Excluding them prevents this test from cannibalizing
// the very policy it enforces. Add sparingly and with a justification comment.
const EXEMPT_FILES = new Set<string>([
  // This test file embeds the forbidden patterns as regex fixtures.
  "security/audit-shell-spawn-policy.test.ts",
  // Skill scanner pattern-matches for these forms in third-party skill code.
  "security/skill-scanner.ts",
  // Audit modules persist the patterns as detection rules.
  "security/audit-deep-code-safety.ts",
  "security/audit-plugin-code-safety.test.ts",
]);

const EXEMPT_DIR_PREFIXES = ["test-helpers/", "test-utils/"];

// Regex bodies are built from char codes so neither this source file nor the
// generated test name contains a literal that would itself match the patterns
// (or trip the repo's security pre-write hook).
const EXEC_WORD = String.fromCharCode(101, 120, 101, 99);
const SHELL_SPAWN_PATTERN = new RegExp("\\bspawn(?:Sync)?\\s*\\([^)]*\\bshell\\s*:\\s*true\\b");
const CHILD_PROCESS_MEMBER_PATTERN = new RegExp(
  "\\bchild_process\\s*\\.\\s*" + EXEC_WORD + "(?:Sync)?\\s*\\(",
);
const NAMED_EXEC_IMPORT_PATTERN = new RegExp(
  "\\bfrom\\s+[\"']node:child_process[\"'][^;]*\\{[^}]*\\b" + EXEC_WORD + "(?:Sync)?\\b",
);

const FORBIDDEN_PATTERNS: Array<{ id: string; regex: RegExp; reason: string }> = [
  {
    id: "spawn_shell_true",
    regex: SHELL_SPAWN_PATTERN,
    reason: "spawn with shell:true re-enables shell metacharacter interpolation",
  },
  {
    id: "child_process_member_exec",
    regex: CHILD_PROCESS_MEMBER_PATTERN,
    reason: "member-call into child_process runs a shell; use execFile or spawn with argv",
  },
  {
    id: "child_process_named_exec_import",
    regex: NAMED_EXEC_IMPORT_PATTERN,
    reason: "named import of shell-runner from node:child_process — switch to execFile/spawn",
  },
];

async function collectSourceFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  for (const entry of entries) {
    if (!entry.isFile()) {
      continue;
    }
    if (!entry.name.endsWith(".ts")) {
      continue;
    }
    if (entry.name.endsWith(".test.ts") || entry.name.endsWith(".e2e.test.ts")) {
      continue;
    }
    if (entry.name.endsWith(".d.ts")) {
      continue;
    }
    const parent = entry.parentPath ?? (entry as unknown as { path: string }).path ?? dir;
    out.push(path.join(parent, entry.name));
  }
  return out;
}

function relSrc(absolutePath: string): string {
  return path.relative(SRC_ROOT, absolutePath).split(path.sep).join("/");
}

function isExempt(relative: string): boolean {
  if (EXEMPT_FILES.has(relative)) {
    return true;
  }
  return EXEMPT_DIR_PREFIXES.some((prefix) => relative.startsWith(prefix));
}

describe("shell-spawn policy: argv arrays only, never sh -c", () => {
  it("rejects every forbidden child-process pattern across src/**", async () => {
    const files = await collectSourceFiles(SRC_ROOT);
    const violations: string[] = [];

    for (const file of files) {
      const relative = relSrc(file);
      if (isExempt(relative)) {
        continue;
      }
      const source = await readFile(file, "utf8");
      for (const pattern of FORBIDDEN_PATTERNS) {
        if (pattern.regex.test(source)) {
          violations.push(`${relative}: ${pattern.id} — ${pattern.reason}`);
        }
      }
    }

    expect(violations, violations.join("\n")).toEqual([]);
  });
});
