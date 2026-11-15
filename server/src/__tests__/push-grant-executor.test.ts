import { describe, expect, it } from "vitest";
import { canonicalGitHubRemoteUrl, githubPushGrantForge, PushGrantForgeError } from "../services/push-grant-executor.js";

const OLD = "1f602c24618f89215bf714c0b80aee3447866efd";
const NEW = "2aba7b069562445dd71316b61e5328de3bd53362";

function recorder(responses: Record<string, string> = {}, failOn?: string) {
  const calls: Array<{ args: string[]; env: Record<string, string> }> = [];
  const execGit = async (args: string[], options: { env: Record<string, string> }) => {
    calls.push({ args, env: options.env });
    const verb = args.find((arg) => ["ls-remote", "init", "fetch", "merge-base", "push"].includes(arg)) ?? "";
    if (failOn && verb === failOn) throw new Error("boom https://x-access-token:secret@github.com");
    return { stdout: responses[verb] ?? "" };
  };
  return { calls, execGit };
}

const noAuth = async () => null;

describe("githubPushGrantForge (ACC-4931)", () => {
  it("accepts only canonical owner/name GitHub repositories", () => {
    expect(canonicalGitHubRemoteUrl("AC-CREATION-AI/AC-NativeNX")).toBe("https://github.com/AC-CREATION-AI/AC-NativeNX.git");
    for (const bad of ["../x", "a/b/c", "https://github.com/a/b", "a", "-a/b", "a/..", "a b/c"]) {
      expect(() => canonicalGitHubRemoteUrl(bad)).toThrow(PushGrantForgeError);
    }
  });

  it("reads the exact remote head with isolated configuration", async () => {
    const { calls, execGit } = recorder({ "ls-remote": `${OLD}\trefs/heads/fix/a\n` });
    const forge = githubPushGrantForge(noAuth, { execGit });
    expect(await forge.readRemoteHead({ repository: "o/r", ref: "refs/heads/fix/a" })).toBe(OLD);
    expect(calls[0]!.args).toEqual(expect.arrayContaining(["ls-remote", "--refs", "--", "https://github.com/o/r.git", "refs/heads/fix/a"]));
    expect(calls[0]!.env).toMatchObject({ GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" });
  });

  it("returns null for a missing ref and fails closed on an unreachable forge without leaking credentials", async () => {
    expect(await githubPushGrantForge(noAuth, { execGit: recorder().execGit }).readRemoteHead({ repository: "o/r", ref: "refs/heads/a" })).toBeNull();
    const failing = githubPushGrantForge(noAuth, { execGit: recorder({}, "ls-remote").execGit });
    await expect(failing.readRemoteHead({ repository: "o/r", ref: "refs/heads/a" })).rejects.toMatchObject({ code: "remote_unavailable" });
    await expect(failing.readRemoteHead({ repository: "o/r", ref: "refs/heads/a" })).rejects.not.toThrow(/secret/);
  });

  it("publishes from a server-owned bare copy with a lease and never a plain force", async () => {
    const { calls, execGit } = recorder();
    const forge = githubPushGrantForge(noAuth, { execGit });
    await forge.push({ repository: "o/r", ref: "refs/heads/fix/a", expectedOldSha: OLD, newSha: NEW, mode: "force-with-lease", sourceCwd: "/workspace/repo" });
    const push = calls.find((call) => call.args.includes("push"))!;
    expect(push.args).toEqual(expect.arrayContaining([
      "--no-verify", `--force-with-lease=refs/heads/fix/a:${OLD}`, "--", "https://github.com/o/r.git", `${NEW}:refs/heads/fix/a`,
    ]));
    expect(push.args).toEqual(expect.arrayContaining(["core.hooksPath=/dev/null"]));
    const flat = calls.flatMap((call) => call.args);
    for (const forbidden of ["--force", "-f", "--delete", "--mirror", "--tags", "--all"]) expect(flat).not.toContain(forbidden);
    const fetch = calls.find((call) => call.args.includes("fetch"))!;
    expect(fetch.args.slice(-2)).toEqual(["/workspace/repo", NEW]);
  });

  it("checks ancestry before a fast-forward push and refuses a non fast-forward", async () => {
    const ok = recorder();
    await githubPushGrantForge(noAuth, { execGit: ok.execGit })
      .push({ repository: "o/r", ref: "refs/heads/a", expectedOldSha: OLD, newSha: NEW, mode: "fast-forward", sourceCwd: "/w" });
    expect(ok.calls.some((call) => call.args.includes("merge-base"))).toBe(true);
    const ko = recorder({}, "merge-base");
    await expect(githubPushGrantForge(noAuth, { execGit: ko.execGit })
      .push({ repository: "o/r", ref: "refs/heads/a", expectedOldSha: OLD, newSha: NEW, mode: "fast-forward", sourceCwd: "/w" }))
      .rejects.toMatchObject({ code: "not_fast_forward" });
    expect(ko.calls.some((call) => call.args.includes("push"))).toBe(false);
  });

  it("refuses unstructured refs, SHAs, modes and relative sources before running git", async () => {
    const { calls, execGit } = recorder();
    const forge = githubPushGrantForge(noAuth, { execGit });
    const base = { repository: "o/r", ref: "refs/heads/a", expectedOldSha: OLD, newSha: NEW, mode: "force-with-lease" as const, sourceCwd: "/w" };
    for (const overrides of [{ ref: "refs/tags/v1" }, { ref: "refs/heads/a/../b" }, { newSha: "HEAD" }, { mode: "force" }, { sourceCwd: "w" }]) {
      await expect(forge.push({ ...base, ...overrides } as never)).rejects.toBeInstanceOf(PushGrantForgeError);
    }
    expect(calls).toHaveLength(0);
  });
});
