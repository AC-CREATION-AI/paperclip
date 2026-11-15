import { execFile as execFileCallback } from "node:child_process";
import type { Dirent } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { PushGrantMode } from "@paperclipai/shared";
import type { GitAuthInvocation, GitRemoteAuthProvider } from "./git-credentials.js";
import { scrubGitCredentialText } from "./git-credentials.js";

/**
 * Forge operations used by the push-grant authority (ACC-4931).
 *
 * This module is the only place in `server/src` allowed to publish to a git
 * remote. It never accepts a command line: every argument is a validated,
 * structured field. Only `fast-forward` and `force-with-lease` exist; there is
 * no code path for `--force`, `--delete`, `--mirror`, tags or wildcards.
 */
export interface PushGrantForgeClient {
  /** Current remote head of `ref`, `null` when the ref does not exist. Throws when the forge is unreachable. */
  readRemoteHead(input: { repository: string; ref: string }): Promise<string | null>;
  /** Publish `newSha` to `ref` only if the remote still points at `expectedOldSha`. Throws on any failure. */
  push(input: {
    repository: string;
    ref: string;
    expectedOldSha: string;
    newSha: string;
    mode: PushGrantMode;
    sourceCwd: string;
  }): Promise<void>;
}

export class PushGrantForgeError extends Error {
  constructor(
    readonly code:
      | "invalid_repository"
      | "source_missing"
      | "source_unavailable"
      | "not_fast_forward"
      | "remote_unavailable"
      | "push_failed",
    message: string,
  ) {
    super(message);
  }
}

const REPOSITORY_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const REF_RE = /^refs\/heads\/[A-Za-z0-9_.\/-]+$/;
const GIT_TIMEOUT_MS = 60_000;

/** `owner/name` → canonical GitHub HTTPS URL; rejects anything else. */
export function canonicalGitHubRemoteUrl(repository: string) {
  if (!REPOSITORY_RE.test(repository) || repository.split("/").some((part) => part === "." || part === ".." || part.startsWith("-"))) {
    throw new PushGrantForgeError("invalid_repository", "Repository must be a canonical owner/name GitHub repository");
  }
  return `https://github.com/${repository.replace(/\.git$/i, "")}.git`;
}

function assertStructured(ref: string, ...shas: string[]) {
  if (!REF_RE.test(ref) || ref.includes("..") || ref.endsWith("/") || ref.endsWith(".lock")) {
    throw new PushGrantForgeError("invalid_repository", "Ref must be a single refs/heads/* branch");
  }
  for (const sha of shas) {
    if (!SHA_RE.test(sha)) throw new PushGrantForgeError("invalid_repository", "SHA must be 40 lowercase hex characters");
  }
}

function isInside(child: string, parent: string) {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

/**
 * Confine the run workspace used as the object source (ACC-4966 B3).
 *
 * Fails closed with `source_unavailable` when the workspace resolves outside
 * the instance's workspace roots, when `.git` is not a plain directory (a
 * `gitdir:` file or a symlink pointing at another repository), or when the
 * object store borrows objects from elsewhere: `objects/info/alternates`, a
 * `commondir` file, or a symlink anywhere under `.git/objects` (ACC-4974 N2).
 * Returns the resolved workspace path to fetch from.
 */
export async function assertConfinedPushSource(sourceCwd: string, allowedRoots: readonly string[]): Promise<string> {
  const refuse = (message: string): never => {
    throw new PushGrantForgeError("source_unavailable", message);
  };
  if (!path.isAbsolute(sourceCwd)) refuse("Run workspace is not an absolute path");
  let resolved: string;
  try {
    resolved = await fs.realpath(sourceCwd);
  } catch {
    return refuse("Run workspace is not available");
  }
  const roots: string[] = [];
  for (const root of allowedRoots) {
    try {
      roots.push(await fs.realpath(root));
    } catch {
      // A root that does not exist on this instance confines nothing.
    }
  }
  if (!roots.some((root) => isInside(resolved, root))) refuse("Run workspace is outside the allowed workspace roots");
  const gitDir = path.join(resolved, ".git");
  let gitStat: Awaited<ReturnType<typeof fs.lstat>>;
  try {
    gitStat = await fs.lstat(gitDir);
  } catch {
    return refuse("Run workspace is not a git repository");
  }
  if (!gitStat.isDirectory()) refuse("Run workspace .git must be a directory, not a gitdir link");
  // A linked worktree reads its object store through `commondir` (ACC-4974 N2).
  const hasCommondir = await fs.lstat(path.join(gitDir, "commondir")).then(() => true, () => false);
  if (hasCommondir) refuse("Run workspace shares its object store through commondir");
  const objectsDir = path.join(gitDir, "objects");
  let objectsStat: Awaited<ReturnType<typeof fs.lstat>>;
  try {
    objectsStat = await fs.lstat(objectsDir);
  } catch {
    return refuse("Run workspace has no object store");
  }
  if (!objectsStat.isDirectory()) refuse("Run workspace .git/objects must be a directory, not a link");
  // Any symlink inside the object store (objects/info, objects/pack, a loose
  // object directory or file) may borrow objects from another repository.
  if (await containsSymlink(objectsDir)) refuse("Run workspace object store links outside itself");
  const alternates = path.join(objectsDir, "info", "alternates");
  const hasAlternates = await fs.lstat(alternates).then(() => true, () => false);
  if (hasAlternates) refuse("Run workspace borrows objects from another repository");
  return resolved;
}

/** True when `dir` (a real directory) contains a symbolic link at any depth. Fails closed on read errors. */
async function containsSymlink(dir: string): Promise<boolean> {
  let entries: Dirent[];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return true;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) return true;
    if (entry.isDirectory() && await containsSymlink(path.join(dir, entry.name))) return true;
  }
  return false;
}

type ExecGit = (args: string[], options: { cwd?: string; env: Record<string, string> }) => Promise<{ stdout: string }>;

const execFile = promisify(execFileCallback);

const defaultExecGit: ExecGit = async (args, options) => {
  const result = await execFile("git", args, {
    cwd: options.cwd,
    env: options.env,
    timeout: GIT_TIMEOUT_MS,
    maxBuffer: 4 * 1024 * 1024,
  });
  return { stdout: String(result.stdout) };
};

/** Never read operator or agent-controlled global/system git configuration. */
function isolatedEnv(auth: GitAuthInvocation | null): Record<string, string> {
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: os.tmpdir(),
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: "",
    SSH_ASKPASS: "",
    ...(auth?.env ?? {}),
  };
}

const HARDENING_ARGS = [
  "-c", "core.hooksPath=/dev/null",
  "-c", "protocol.allow=never",
  "-c", "protocol.https.allow=always",
  "-c", "protocol.file.allow=always",
  "-c", "transfer.fsckObjects=true",
];

export function githubPushGrantForge(
  resolveAuth: GitRemoteAuthProvider,
  deps: { execGit?: ExecGit } = {},
): PushGrantForgeClient {
  const execGit = deps.execGit ?? defaultExecGit;

  async function authFor(url: string) {
    const auth = await resolveAuth(url);
    return { args: [...HARDENING_ARGS, ...(auth?.configArgs ?? [])], env: isolatedEnv(auth) };
  }

  return {
    async readRemoteHead({ repository, ref }) {
      assertStructured(ref);
      const url = canonicalGitHubRemoteUrl(repository);
      const { args, env } = await authFor(url);
      let stdout: string;
      try {
        ({ stdout } = await execGit([...args, "ls-remote", "--refs", "--", url, ref], { env }));
      } catch (error) {
        throw new PushGrantForgeError("remote_unavailable", scrubGitCredentialText(error instanceof Error ? error.message : String(error)));
      }
      const matches = stdout.split("\n").map((line) => line.trim().split(/\s+/)).filter(([, name]) => name === ref);
      if (matches.length === 0) return null;
      if (matches.length > 1 || !SHA_RE.test(matches[0]![0]!.toLowerCase())) {
        throw new PushGrantForgeError("remote_unavailable", "Ambiguous remote head");
      }
      return matches[0]![0]!.toLowerCase();
    },

    async push({ repository, ref, expectedOldSha, newSha, mode, sourceCwd }) {
      assertStructured(ref, expectedOldSha, newSha);
      if (mode !== "fast-forward" && mode !== "force-with-lease") {
        throw new PushGrantForgeError("push_failed", "Unsupported push mode");
      }
      if (!path.isAbsolute(sourceCwd)) throw new PushGrantForgeError("source_missing", "Run workspace is not available");
      const url = canonicalGitHubRemoteUrl(repository);
      // The agent workspace is untrusted (hooks, config, alternates). Copy only the
      // objects into a server-owned bare repository and publish from there.
      const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-push-grant-"));
      try {
        const env = isolatedEnv(null);
        await execGit([...HARDENING_ARGS, "init", "--quiet", "--bare", scratch], { env });
        try {
          await execGit([...HARDENING_ARGS, "-C", scratch, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--", sourceCwd, newSha], { env });
        } catch {
          throw new PushGrantForgeError("source_missing", "newSha is not available in the run workspace");
        }
        if (mode === "fast-forward") {
          try {
            await execGit([...HARDENING_ARGS, "-C", scratch, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--", sourceCwd, expectedOldSha], { env });
            await execGit([...HARDENING_ARGS, "-C", scratch, "merge-base", "--is-ancestor", expectedOldSha, newSha], { env });
          } catch {
            throw new PushGrantForgeError("not_fast_forward", "newSha does not descend from expectedOldSha");
          }
        }
        const auth = await authFor(url);
        try {
          // The lease is checked atomically by the remote. For fast-forward the
          // ancestry check above guarantees the update is a fast-forward.
          // paperclip:allow-git-push: push grant execution authority (ACC-4931), structured fields only, lease enforced
          await execGit([...auth.args, "-C", scratch, "push", "--porcelain", "--no-verify", `--force-with-lease=${ref}:${expectedOldSha}`, "--", url, `${newSha}:${ref}`], { env: auth.env });
        } catch (error) {
          throw new PushGrantForgeError("push_failed", scrubGitCredentialText(error instanceof Error ? error.message : String(error)));
        }
      } finally {
        await fs.rm(scratch, { recursive: true, force: true });
      }
    },
  };
}
