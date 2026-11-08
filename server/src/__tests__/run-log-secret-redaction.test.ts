import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { Db } from "@paperclipai/db";
import { companySecretVersions } from "@paperclipai/db";
import { REDACTED_EVENT_VALUE } from "../redaction.js";
import { createRunSecretRedactionRegistry } from "../services/run-secret-redaction.js";

const { resolveVersion, resolveBoundValues } = vi.hoisted(() => ({
  resolveVersion: vi.fn(async ({ material }) => material.value as string),
  resolveBoundValues: vi.fn(async () => [] as string[]),
}));
vi.mock("../secrets/provider-registry.js", () => ({ getSecretProvider: () => ({ resolveVersion }) }));
vi.mock("../services/secrets.js", () => ({
  secretService: () => ({ resolveSecretValuesForRunRedaction: resolveBoundValues }),
}));

function sha256(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function fixture(input: {
  registryEntries?: Array<{ value: string }>;
  versionRows?: Array<{ fingerprintSha256?: string | null; valueSha256?: string | null }>;
}) {
  const runRows = [{
    contextSnapshot: {
      paperclipSecretRedactions: (input.registryEntries ?? []).map((entry) => ({
        fingerprintSha256: sha256(entry.value),
        material: { value: entry.value },
      })),
    },
    credentialConnectionName: null,
  }];
  const versionRows = input.versionRows ?? [];
  const runWhere = vi.fn(async () => runRows);
  const versionWhere = vi.fn(async () => versionRows);
  const pick = (table: unknown) => (table === companySecretVersions ? versionWhere : runWhere);
  const select = vi.fn(() => ({
    from: (table: unknown) => ({
      innerJoin: () => ({ where: pick(table) }),
      where: pick(table),
    }),
  }));
  return {
    registry: createRunSecretRedactionRegistry({ select } as unknown as Db),
    run: { id: "run-1", agentId: "agent-1" },
  };
}

describe("run log secret redaction (ACC-3241)", () => {
  it("masks registered disclosure values in served log chunks", async () => {
    const { registry, run } = fixture({ registryEntries: [{ value: "registered-secret-value" }] });
    const out = await registry.redactRunLog("company-1", run, {
      content: "tool output registered-secret-value end",
    });
    expect(out.content).toBe(`tool output ${REDACTED_EVENT_VALUE} end`);
  });

  it("masks values bound to the run's agent even under unrelated header names", async () => {
    resolveBoundValues.mockResolvedValueOnce(["k9Zq4Xw7Lm2Np8Rt5Vc3Yb6Hj0Fd1Sg4Ua7Ke2Oi5Zx8Qn3"]);
    const { registry, run } = fixture({});
    const token = "k9Zq4Xw7Lm2Np8Rt5Vc3Yb6Hj0Fd1Sg4Ua7Ke2Oi5Zx8Qn3";
    const out = await registry.redactRunLog("company-1", run, {
      content: `X-Paperclip-Api-Key: ${token}\nX-Board-Key: ${token}`,
    });
    expect(out.content).not.toContain(token);
    expect(out.content).toBe(`X-Paperclip-Api-Key: ${REDACTED_EVENT_VALUE}\nX-Board-Key: ${REDACTED_EVENT_VALUE}`);
    expect(resolveBoundValues).toHaveBeenCalledWith("company-1", { agentId: "agent-1", runId: "run-1" });
  });

  it("masks active company secret values matched by fingerprint without resolving them", async () => {
    const leaked = "7f3ab19c-4e5d-6a7b-8c9d-0e1f2a3b4c5d";
    const { registry, run } = fixture({ versionRows: [{ fingerprintSha256: sha256(leaked) }] });
    const out = await registry.redactRunLog("company-1", run, {
      content: `stdout wrote ${leaked} to the log`,
    });
    expect(out.content).toBe(`stdout wrote ${REDACTED_EVENT_VALUE} to the log`);
  });

  it("masks secret family shapes (pcp_board_, PEM, JWT) in log chunks", async () => {
    const { registry, run } = fixture({});
    const boardToken = `pcp_board_${"362545d61d".repeat(5)}`;
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA";
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const out = await registry.redactRunLog("company-1", run, {
      content: `X-Paperclip-Api-Key: ${boardToken}\n${pem}\nset-cookie: sid=${jwt}`,
    });
    expect(out.content).not.toContain(boardToken);
    expect(out.content).not.toContain("b3BlbnNzaC1rZXktdjEAAAAA");
    expect(out.content).not.toContain(jwt);
  });

  it("masks truncated fragments of known values (C7 debug prefix)", async () => {
    const full = `${"Qm3xK9pL7rT2wZ5n".repeat(12)}`; // 192 chars of key material
    const prefix = full.slice(0, 82);
    resolveBoundValues.mockResolvedValueOnce([full]);
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, {
      content: `debug dump: ${prefix}`,
    });
    expect(out.content).toBe(`debug dump: ${REDACTED_EVENT_VALUE}`);
  });

  it("leaves non-secret log content untouched", async () => {
    const { registry, run } = fixture({});
    const content = "2026-11-08 build ok feature/acc-3241 (42s)";
    const out = await registry.redactRunLog("company-1", run, { content });
    expect(out.content).toBe(content);
  });
});
