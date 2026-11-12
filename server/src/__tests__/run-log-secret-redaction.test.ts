import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { Db } from "@paperclipai/db";
import { companySecretVersions } from "@paperclipai/db";
import { REDACTED_EVENT_VALUE } from "../redaction.js";
import { compactRunLogChunk } from "../services/heartbeat/run-log.js";
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

  it("masks fragments glued to a variable name or followed by an ellipsis", async () => {
    const full = `${"Qm3xK9pL7rT2wZ5n".repeat(12)}`;
    const prefix = full.slice(0, 82);
    resolveBoundValues.mockResolvedValueOnce([full]);
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, {
      content: `API_TOKEN=${prefix}\nvalue: ${prefix}...\n`,
    });
    expect(out.content).not.toContain(prefix);
    expect(out.content).toBe(`API_TOKEN=${REDACTED_EVENT_VALUE}\nvalue: ${REDACTED_EVENT_VALUE}...\n`);
  });
});

// The served log is NDJSON written by the run log store (run-log-store.ts):
// one JSON record per event, tool text JSON-escaped inside `chunk`.
function ndjson(chunk: string, seq = 1) {
  return `${JSON.stringify({ ts: "2026-11-08T00:00:00.000Z", stream: "stdout", chunk, seq })}\n`;
}

function chunks(content: string) {
  return content.split("\n").filter(Boolean).map((line) => (JSON.parse(line) as { chunk: string }).chunk);
}

const PEM_BODY = [
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
  "QyNTUxOQAAACBQaXN0YWNoZUZha2VLZXlGb3JRQVByb2JlT25seTEyMzQ1Njc4OQAAAJg",
];
const PEM = `-----BEGIN OPENSSH PRIVATE KEY-----\n${PEM_BODY.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`;

describe("run log secret redaction on served NDJSON records (ACC-3241 rework)", () => {
  it("masks a bound PEM key printed by a tool and keeps the record valid JSON", async () => {
    resolveBoundValues.mockResolvedValueOnce([PEM]);
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(`$ cat key\n${PEM}`) });
    for (const line of PEM_BODY) expect(out.content).not.toContain(line);
    expect(chunks(out.content)).toEqual([`$ cat key\n${REDACTED_EVENT_VALUE}`]);
  });

  it("collapses an unknown PEM key by family pattern inside a record", async () => {
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(PEM) });
    for (const line of PEM_BODY) expect(out.content).not.toContain(line);
    expect(chunks(out.content)[0]).toContain("-----BEGIN OPENSSH PRIVATE KEY-----");
  });

  it("masks a C7 prefix of a bound value inside a record (debug dump)", async () => {
    const full = `${"Qm3xK9pL7rT2wZ5n".repeat(12)}`;
    const prefix = full.slice(0, 82);
    resolveBoundValues.mockResolvedValueOnce([full]);
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(`debug dump: ${prefix}\n`) });
    expect(out.content).not.toContain(prefix);
    expect(chunks(out.content)).toEqual([`debug dump: ${REDACTED_EVENT_VALUE}\n`]);
  });

  it("masks a fingerprinted company secret in the middle of a record", async () => {
    const leaked = "7f3ab19c-4e5d-6a7b-8c9d-0e1f2a3b4c5d";
    const { registry, run } = fixture({ versionRows: [{ fingerprintSha256: sha256(leaked) }] });
    const out = await registry.redactRunLog("company-1", run, {
      content: ndjson(`stdout wrote ${leaked} to the log\nexport TOKEN="${leaked}"\n`),
    });
    expect(out.content).not.toContain(leaked);
    expect(chunks(out.content)).toEqual([
      `stdout wrote ${REDACTED_EVENT_VALUE} to the log\nexport TOKEN="${REDACTED_EVENT_VALUE}"\n`,
    ]);
  });

  it("masks a fingerprinted value inside minified JSON tool output", async () => {
    const leaked = "7f3ab19c-4e5d-6a7b-8c9d-0e1f2a3b4c5d";
    const filler = Array.from({ length: 2000 }, (_, index) => `"k${index}":${index}`).join(",");
    const { registry, run } = fixture({ versionRows: [{ fingerprintSha256: sha256(leaked) }] });
    const out = await registry.redactRunLog("company-1", run, {
      content: ndjson(`{${filler},"api_key":"${leaked}","ok":true}\n`),
    });
    expect(out.content).not.toContain(leaked);
    expect(chunks(out.content)[0]).toContain(`"api_key":"${REDACTED_EVENT_VALUE}"`);
  });

  it("masks family tokens at the start of a line inside a record", async () => {
    const token = `pcp_board_${"362545d61d".repeat(5)}`;
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(`header\n${token}\n`) });
    expect(out.content).not.toContain(token);
  });

  it("masks registered values whose characters are JSON-escaped in the record", async () => {
    const value = 'pa"ss\\word-with-escapes';
    const { registry, run } = fixture({ registryEntries: [{ value }] });
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(`echo ${value}\n`) });
    expect(chunks(out.content)).toEqual([`echo ${REDACTED_EVENT_VALUE}\n`]);
  });

  it("masks a partial record cut by the page limit", async () => {
    const token = `sk-ant-${"ort01".repeat(8)}`;
    const { registry, run } = fixture({});
    const page = `${ndjson("first\n")}${ndjson(`probe\n${token} and more`, 2).slice(0, -12)}`;
    const out = await registry.redactRunLog("company-1", run, { content: page });
    expect(out.content).not.toContain(token);
    expect(chunks(out.content.split("\n")[0]!)).toEqual(["first\n"]);
  });

  it("masks a partial record that starts mid-chunk", async () => {
    const token = `ghp_${"Qm3xK9pL".repeat(4)}`;
    const record = ndjson(`probe\n${token}\n`);
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: record.slice(record.indexOf("probe")) });
    expect(out.content).not.toContain(token);
  });

  it("masks every stored version of a company secret, rotated ones included", async () => {
    const oldValue = "old-rotated-value-abcdefghijklmnopqrstuvwxyz012345";
    const { registry, run } = fixture({
      versionRows: [{ fingerprintSha256: sha256("current-other-value") }, { valueSha256: sha256(oldValue) }],
    });
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(`written before rotation: ${oldValue}`) });
    expect(out.content).not.toContain(oldValue);
  });

  it("leaves ordinary records byte-identical", async () => {
    const { registry, run } = fixture({});
    const content = `${ndjson("2026-11-08 build ok feature/acc-3241 (42s)\n")}${ndjson('{"type":"result","ok":true}\n', 2)}`;
    const out = await registry.redactRunLog("company-1", run, { content });
    expect(out.content).toBe(content);
  });

  it("masks through the full write -> store -> read pipeline", async () => {
    const full = `${"Qm3xK9pL7rT2wZ5n".repeat(12)}`;
    const leaked = "7f3ab19c-4e5d-6a7b-8c9d-0e1f2a3b4c5d";
    resolveBoundValues.mockResolvedValueOnce([full]);
    const { registry, run } = fixture({ versionRows: [{ fingerprintSha256: sha256(leaked) }] });
    const stored = [
      `debug dump: ${full.slice(0, 82)}`,
      `stdout wrote ${leaked} to the log`,
      `cat key\n${PEM}`,
    ].map((chunk, index) => ndjson(compactRunLogChunk(chunk), index + 1)).join("");
    const out = await registry.redactRunLog("company-1", run, { content: stored });
    expect(out.content).not.toContain(full.slice(0, 82));
    expect(out.content).not.toContain(leaked);
    for (const line of PEM_BODY) expect(out.content).not.toContain(line);
  });
});

// A claude_local / `engine: acp` run log: each stdout chunk is itself a JSON
// event (acpx-engine/execute.ts) whose `text` carries the tool output, so the
// served log escapes that output twice.
function acpxToolCall(text: string) {
  return `${JSON.stringify({
    type: "acpx.tool_call",
    name: "Terminal",
    toolCallId: "call-1",
    status: "completed",
    text,
  })}\n`;
}

function toolTexts(content: string) {
  return chunks(content).map((chunk) => (JSON.parse(chunk) as { text: string }).text);
}

describe("run log secret redaction on ACP run logs (ACC-3241, output escaped twice)", () => {
  it("masks a bound PEM key printed by a tool", async () => {
    resolveBoundValues.mockResolvedValueOnce([PEM]);
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(acpxToolCall(`$ cat key\n${PEM}`)) });
    for (const line of PEM_BODY) expect(out.content).not.toContain(line);
    expect(toolTexts(out.content)).toEqual([`$ cat key\n${REDACTED_EVENT_VALUE}`]);
  });

  it("collapses an unknown PEM key by family pattern", async () => {
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(acpxToolCall(PEM)) });
    for (const line of PEM_BODY) expect(out.content).not.toContain(line);
    expect(toolTexts(out.content)[0]).toContain("-----BEGIN OPENSSH PRIVATE KEY-----");
  });

  it("masks family tokens at the start of a line of tool output", async () => {
    const tokens = [
      `pcp_board_${"362545d61d".repeat(5)}`,
      `ghp_${"Qm3xK9pL".repeat(4)}`,
      `sk-ant-${"ort01".repeat(8)}`,
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcm9iZSJ9.c2lnbmF0dXJlLXByb2Jl",
    ];
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, {
      content: ndjson(acpxToolCall(`header\n${tokens.join("\n")}\n`)),
    });
    for (const token of tokens) expect(out.content).not.toContain(token);
  });

  it("masks a fingerprinted company secret on its own line of tool output", async () => {
    const leaked = "7f3ab19c-4e5d-6a7b-8c9d-0e1f2a3b4c5d";
    const { registry, run } = fixture({ versionRows: [{ fingerprintSha256: sha256(leaked) }] });
    const out = await registry.redactRunLog("company-1", run, {
      content: ndjson(acpxToolCall(`HOST=localhost\nAPI_TOKEN=${leaked}\nDEBUG=1\n`)),
    });
    expect(out.content).not.toContain(leaked);
    expect(toolTexts(out.content)).toEqual([`HOST=localhost\nAPI_TOKEN=${REDACTED_EVENT_VALUE}\nDEBUG=1\n`]);
  });

  it("masks a PEM held in a JSON string of pretty-printed tool output", async () => {
    const { registry, run } = fixture({});
    const output = JSON.stringify({ name: "fleet_ssh_key", value: PEM }, null, 2);
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(acpxToolCall(output)) });
    for (const line of PEM_BODY) expect(out.content).not.toContain(line);
    expect(JSON.parse(toolTexts(out.content)[0]!)).toEqual({
      name: "fleet_ssh_key",
      value: `-----BEGIN OPENSSH PRIVATE KEY-----\n${REDACTED_EVENT_VALUE}\n-----END OPENSSH PRIVATE KEY-----\n`,
    });
  });

  it("masks a record cut by the page limit", async () => {
    const token = `sk-ant-${"ort01".repeat(8)}`;
    const { registry, run } = fixture({});
    const page = `${ndjson("first\n")}${ndjson(acpxToolCall(`probe\n${token} and more`), 2).slice(0, -12)}`;
    const out = await registry.redactRunLog("company-1", run, { content: page });
    expect(out.content).not.toContain(token);
  });

  it("masks at write time, before the chunk is stored", () => {
    const token = `ghp_${"Qm3xK9pL".repeat(4)}`;
    const stored = compactRunLogChunk(acpxToolCall(`$ cat key\n${PEM}${token}\n`));
    for (const line of PEM_BODY) expect(stored).not.toContain(line);
    expect(stored).not.toContain(token);
    expect(JSON.parse(stored)).toMatchObject({ type: "acpx.tool_call", toolCallId: "call-1" });
  });

  it("masks through the full write -> store -> read pipeline", async () => {
    const leaked = "7f3ab19c-4e5d-6a7b-8c9d-0e1f2a3b4c5d";
    const { registry, run } = fixture({ versionRows: [{ fingerprintSha256: sha256(leaked) }] });
    const stored = [`cat key\n${PEM}`, `HOST=localhost\nAPI_TOKEN=${leaked}\n`]
      .map((text, index) => ndjson(compactRunLogChunk(acpxToolCall(text)), index + 1)).join("");
    const out = await registry.redactRunLog("company-1", run, { content: stored });
    for (const line of PEM_BODY) expect(out.content).not.toContain(line);
    expect(out.content).not.toContain(leaked);
  });

  it("leaves ordinary ACP records byte-identical, on read and on write", async () => {
    const events = [
      acpxToolCall("total 8\ndrwxr-xr-x 2 pcagent pcagent 4096 Nov  8 build\n\"quoted\" \\ path\n"),
      `${JSON.stringify({ type: "acpx.text_delta", text: "Je relance les tests.\n" })}\n`,
      acpxToolCall(JSON.stringify({ ok: true, items: [{ id: "a1", note: "line\nbreak" }] }, null, 2)),
    ];
    const { registry, run } = fixture({});
    const content = events.map((event, index) => ndjson(event, index + 1)).join("");
    const out = await registry.redactRunLog("company-1", run, { content });
    expect(out.content).toBe(content);
    for (const event of events) expect(compactRunLogChunk(event)).toBe(event);
  });
});

// A hub MCP tool reached through `run_tool`: the ACP event text wraps the
// gateway envelope, whose `text` holds the tool output, often pretty-printed
// JSON. That output sits four levels of escaping below the served record.
function acpxRunToolResult(output: string) {
  return acpxToolCall(`tool call (completed): ${JSON.stringify({
    content: [{ type: "text", text: output }],
    structuredContent: null,
    isError: false,
    transport: "mcp_http",
    spawnedLocalProcess: false,
  })}`);
}

describe("run log secret redaction on hub MCP tool output (ACC-3241, run_tool envelope)", () => {
  const prettyItem = (pem: string) => JSON.stringify({ name: "deploy key", sshKey: { privateKey: pem } }, null, 2);
  // A short last base64 line stays under the fragment pass threshold on its own.
  const body = [...PEM_BODY, "ZmFrZWtleXRhaWw="];
  const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${body.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`;

  it("collapses an unknown PEM in pretty-printed JSON of an already stored log", async () => {
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(acpxRunToolResult(prettyItem(pem))) });
    for (const line of body) expect(out.content).not.toContain(line);
    expect(JSON.parse(chunks(out.content)[0]!)).toMatchObject({ type: "acpx.tool_call", toolCallId: "call-1" });
  });

  it("masks every line of a bound PEM in the same output", async () => {
    resolveBoundValues.mockResolvedValueOnce([pem]);
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(acpxRunToolResult(prettyItem(pem))) });
    for (const line of body) expect(out.content).not.toContain(line);
  });

  it("masks the same output at write time", () => {
    const stored = compactRunLogChunk(acpxRunToolResult(prettyItem(pem)));
    for (const line of body) expect(stored).not.toContain(line);
  });

  it("leaves an ordinary run_tool result byte-identical, on read and on write", async () => {
    const event = acpxRunToolResult(JSON.stringify([{ name: "paperclip", note: "line\nbreak \"q\"" }], null, 2));
    const { registry, run } = fixture({});
    const content = ndjson(event);
    expect((await registry.redactRunLog("company-1", run, { content })).content).toBe(content);
    expect(compactRunLogChunk(event)).toBe(event);
  });
});

// The ACP runtime truncates every tool summary at 500 characters
// (acpx/dist/runtime.js, `TOOL_OUTPUT_SUMMARY_MAX_CHARS`), in both pinned
// versions (0.12.0 for packages/adapter-utils, 0.13.1 for the server):
//
//   function truncateToolSummary(value) {
//     if (value.length <= TOOL_OUTPUT_SUMMARY_MAX_CHARS) return value;
//     return `${value.slice(0, TOOL_OUTPUT_SUMMARY_MAX_CHARS - 1)}…`;
//   }
//
// A hub MCP tool reached through `run_tool` therefore stores a CUT gateway
// envelope as soon as its output exceeds ~477 characters: the cut falls
// inside a JSON string literal, which no longer has a closing quote. The
// nested passes walked JSON string literals, so they stopped there and the
// secret stayed in clear — on write and on read.
const ACPX_TOOL_OUTPUT_SUMMARY_MAX_CHARS = 500;

function truncateToolSummary(value: string) {
  if (value.length <= ACPX_TOOL_OUTPUT_SUMMARY_MAX_CHARS) return value;
  return `${value.slice(0, ACPX_TOOL_OUTPUT_SUMMARY_MAX_CHARS - 1)}…`;
}

function acpxRunToolResultTruncated(output: string) {
  return acpxToolCall(`tool call (completed): ${truncateToolSummary(JSON.stringify({
    content: [{ type: "text", text: output }],
    structuredContent: null,
    isError: false,
    transport: "mcp_http",
    spawnedLocalProcess: false,
  }))}`);
}

describe("run log secret redaction on a truncated ACP tool summary (ACC-3241)", () => {
  const body = Array.from({ length: 6 }, (_, index) =>
    (`b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW`
      + `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo`.slice(index % 8)).repeat(2).slice(0, 70));
  const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${body.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`;
  const pretty = JSON.stringify({ name: "deploy key", sshKey: { privateKey: pem } }, null, 2);

  it("collapses an unknown PEM when the tool summary was cut by the runtime", async () => {
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(acpxRunToolResultTruncated(pretty)) });
    for (const line of body) expect(out.content).not.toContain(line);
  });

  it("masks the same cut output at write time", () => {
    const stored = compactRunLogChunk(acpxRunToolResultTruncated(pretty));
    for (const line of body) expect(stored).not.toContain(line);
  });

  it("masks a fingerprinted company secret in a cut tool summary", async () => {
    const leaked = "7f3ab19c-4e5d-6a7b-8c9d-0e1f2a3b4c5d";
    const { registry, run } = fixture({ versionRows: [{ fingerprintSha256: sha256(leaked) }] });
    const out = await registry.redactRunLog("company-1", run, {
      content: ndjson(acpxRunToolResultTruncated(JSON.stringify({ db: { password: leaked }, note: "x".repeat(400) }, null, 2))),
    });
    expect(out.content).not.toContain(leaked);
  });

  it("masks a bound PEM in a cut tool summary", async () => {
    resolveBoundValues.mockResolvedValueOnce([pem]);
    const { registry, run } = fixture({});
    const out = await registry.redactRunLog("company-1", run, { content: ndjson(acpxRunToolResultTruncated(pretty)) });
    for (const line of body) expect(out.content).not.toContain(line);
  });
});

describe("run log secret redaction on a cut literal outside JSON (ACC-3241)", () => {
  it("leaves prose carrying a stray quote byte-identical", async () => {
    const { registry, run } = fixture({});
    const content = ndjson(`he said "hello\\n and left\n`);
    const out = await registry.redactRunLog("company-1", run, { content });
    expect(out.content).toBe(content);
  });

  it("leaves a cut literal that does not open a JSON value byte-identical", async () => {
    const { registry, run } = fixture({});
    const content = ndjson(`prefix "unterminated \\n value\n`);
    const out = await registry.redactRunLog("company-1", run, { content });
    expect(out.content).toBe(content);
  });
});
