import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createIssueThreadInteractionSchema, requestConfirmationTargetSchema } from "@paperclipai/shared";
import {
  AGENT_PROFILE_CHANGE_CONSENT_FIELDS,
  agentInstructionsChangeTargetKey,
  agentProfileChangeTargetKey,
} from "../services/change-consent-gate.js";

// ACC-3542: agents sent `payload.target.type: "skill"` / `"resource"` and got
// 400s. The skill reference now lists the accepted target types and which
// custom keys count as change consent; this keeps that page true.
const reference = readFileSync(new URL("../../../skills/paperclip/references/api-reference.md", import.meta.url), "utf8");
const uuid = "11111111-1111-4111-8111-111111111111";
const substituteIds = (body: unknown) => JSON.parse(JSON.stringify(body).replace(/\{[\w-]+\}/g, uuid));

function targetsSection() {
  const section = reference.split('<a id="confirmation-targets"></a>')[1]?.split("\nResolver governance:")[0];
  expect(section, "api-reference.md must keep the #confirmation-targets anchor").toBeTruthy();
  return section!;
}

function publishedExamples() {
  return [...targetsSection().matchAll(/```json\nPOST \/api\/issues\/\{issueId\}\/interactions\n([\s\S]*?)\n```/g)]
    .map((match) => JSON.parse(match[1]));
}

function targetIssues(target: unknown) {
  const body = { ...publishedExamples()[0], payload: { ...publishedExamples()[0].payload, target } };
  const result = createIssueThreadInteractionSchema.safeParse(substituteIds(body));
  return result.success ? [] : result.error.issues.map((issue) => ({ path: issue.path.join("."), code: issue.code }));
}

describe("published request_confirmation target contract", () => {
  it("documents exactly the target types the schema accepts", () => {
    const schemaTypes = requestConfirmationTargetSchema.options.map((option) => option.shape.type.value).sort();
    const documentedTypes = [...targetsSection().matchAll(/^\| `([a-z_]+)` \| /gm)].map((match) => match[1]);
    const typeRows = documentedTypes.filter((type) => schemaTypes.includes(type)).sort();
    expect(schemaTypes).toEqual(["custom", "issue_attachment", "issue_document"]);
    expect(typeRows).toEqual(schemaTypes);
  });

  it("publishes a valid example for each type that is not already in the plan example", () => {
    const examples = publishedExamples();
    expect(examples.map((example) => example.payload.target.type)).toEqual(["issue_attachment", "custom"]);
    for (const example of examples) {
      const parsed = createIssueThreadInteractionSchema.parse(substituteIds(example));
      expect(parsed.kind).toBe("request_confirmation");
    }
  });

  it.each(["skill", "resource", "agent"])("rejects target type %s at payload.target.type", (type) => {
    expect(targetIssues({ type, key: "anything" })).toEqual([{ path: "payload.target.type", code: "invalid_union" }]);
  });

  it("requires the documented fields for each type", () => {
    expect(targetIssues({ type: "custom" })).toEqual([{ path: "payload.target.key", code: "invalid_type" }]);
    expect(targetIssues({ type: "custom", key: "k".repeat(121) })).toEqual([{ path: "payload.target.key", code: "too_big" }]);
    expect(targetIssues({ type: "custom", key: "pr:repo#1", revisionId: "a".repeat(40) })).toEqual([]);
    expect(targetIssues({ type: "issue_document", key: "plan" })).toEqual([{ path: "payload.target.revisionId", code: "invalid_type" }]);
    expect(targetIssues({ type: "issue_document", key: "Plan", revisionId: uuid })).toEqual([{ path: "payload.target.key", code: "invalid_format" }]);
    expect(targetIssues({ type: "issue_attachment", attachmentId: uuid, assetId: uuid, sha256: "ABC" }))
      .toEqual([{ path: "payload.target.sha256", code: "invalid_format" }]);
  });

  it("documents the consent keys and profile fields the server actually checks", () => {
    const section = targetsSection();
    const agentId = "{agentId}";
    expect(section).toContain(`| \`${agentInstructionsChangeTargetKey(agentId)}\` |`);
    expect(section).toContain(`| \`${agentProfileChangeTargetKey(agentId)}\` |`);
    const profileRow = section.split("\n").find((line) => line.startsWith(`| \`${agentProfileChangeTargetKey(agentId)}\``))!;
    for (const field of AGENT_PROFILE_CHANGE_CONSENT_FIELDS) expect(profileRow).toContain(`\`${field}\``);
    expect(section).toContain("POST /api/agents/{agentId}/skills/sync");
    const customExample = publishedExamples().find((example) => example.payload.target.type === "custom")!;
    expect(customExample.payload.target.key).toBe(agentInstructionsChangeTargetKey(agentId));
    expect(customExample.payload.detailsMarkdown).toMatch(/```diff\b/);
  });
});
