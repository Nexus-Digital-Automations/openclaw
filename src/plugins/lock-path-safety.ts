import path from "node:path";

// Shared by the skills.lock and plugins.lock parsers so their path-traversal
// guards cannot drift apart. Both lockfiles are untrusted on read (an author or
// attacker can edit them) and their file keys are later path.join'd against the
// install/plugin root and stat/hashed, so an escaping key turns integrity
// verification into an arbitrary out-of-tree read. A key is safe only if it
// stays inside the root: not absolute, no `\` (a Windows separator that could
// escape), no NUL, and its POSIX normalization is neither `.`/`..` nor begins
// with `../`. Keys are written POSIX-style, so a normalized `../` means traversal.
export function isContainedRelativePath(key: string): boolean {
  if (!key || key.includes("\0") || key.includes("\\") || path.posix.isAbsolute(key)) {
    return false;
  }
  const normalized = path.posix.normalize(key);
  return normalized !== "." && normalized !== ".." && !normalized.startsWith("../");
}
