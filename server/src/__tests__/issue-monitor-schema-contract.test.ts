import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { updateIssueSchema } from "@paperclipai/shared";
import { applyIssueExecutionPolicyTransition, buildInitialIssueMonitorFields, normalizeIssueExecutionPolicy } from "../services/issue-execution-policy.ts";

const coderAgentId = "11111111-1111-4111-8111-111111111111";
const skill = readFileSync(new URL("../../../skills/paperclip/SKILL.md", import.meta.url), "utf8");

function publishedMonitorExample() {
  const section = skill.split('<a id="monitor-payload"></a>')[1];
  expect(section, "skills/paperclip/SKILL.md must keep the #monitor-payload anchor").toBeTruthy();
  return JSON.parse(section!.match(/```json\n([\s\S]*?)\n```/)![1]);
}

function issuesFor(body: unknown) {
  const result = updateIssueSchema.safeParse(body);
  return result.success ? [] : result.error.issues.map(issue => ({ path: issue.path.join("."), message: issue.message }));
}

describe("published monitor payload contract", () => {
  it("accepts the complete monitor example from the paperclip skill", () => {
    const body = publishedMonitorExample();
    const parsed = updateIssueSchema.parse(body);
    expect(parsed.executionPolicy?.monitor).toMatchObject({
      kind: "external_service",
      serviceName: expect.any(String),
      externalRef: expect.any(String),
      nextCheckAt: expect.stringMatching(/Z$/),
      timeoutAt: expect.stringMatching(/Z$/),
      maxAttempts: expect.any(Number),
    });
    const monitor = parsed.executionPolicy!.monitor!;
    expect(Date.parse(monitor.timeoutAt!)).toBeGreaterThan(Date.parse(monitor.nextCheckAt));
  });

  it("schedules the published example on an eligible agent-assigned issue", () => {
    const body = publishedMonitorExample();
    const policy = normalizeIssueExecutionPolicy(updateIssueSchema.parse(body).executionPolicy)!;
    const fields = buildInitialIssueMonitorFields({ policy, status: "in_progress", assigneeAgentId: coderAgentId });
    expect(fields.monitorNextCheckAt?.toISOString()).toBe(new Date(body.executionPolicy.monitor.nextCheckAt).toISOString());
  });

  it("explains how to fix an unsupported kind", () => {
    const body = publishedMonitorExample();
    body.executionPolicy.monitor.kind = "poll";
    expect(issuesFor(body)).toEqual([{
      path: "executionPolicy.monitor.kind",
      message: expect.stringContaining('must be "external_service"'),
    }]);
  });

  it.each(["nextCheckAt", "timeoutAt"])("explains that %s must be UTC ending in Z", (field) => {
    const body = publishedMonitorExample();
    body.executionPolicy.monitor[field] = "2026-11-20T10:00:00+00:00";
    expect(issuesFor(body)).toEqual([{
      path: `executionPolicy.monitor.${field}`,
      message: expect.stringContaining('UTC timestamp ending in "Z"'),
    }]);
  });

  it("keeps accepting fractional-second UTC timestamps", () => {
    const body = publishedMonitorExample();
    body.executionPolicy.monitor.nextCheckAt = "2026-11-20T10:00:00.000Z";
    expect(issuesFor(body)).toEqual([]);
  });

  it("explains how to re-arm a monitor whose attempts are exhausted", () => {
    const policy = normalizeIssueExecutionPolicy({
      stages: [],
      monitor: { nextCheckAt: "2099-04-11T12:30:00.000Z", maxAttempts: 1, scheduledBy: "assignee" },
    })!;
    let error: unknown;
    try {
      applyIssueExecutionPolicyTransition({
        issue: {
          status: "in_progress",
          assigneeAgentId: coderAgentId,
          assigneeUserId: null,
          executionPolicy: null,
          executionState: null,
          monitorAttemptCount: 1,
          monitorNextCheckAt: null,
          monitorLastTriggeredAt: null,
          monitorNotes: null,
          monitorScheduledBy: "assignee",
        },
        policy,
        previousPolicy: null,
        requestedAssigneePatch: {},
        actor: { agentId: coderAgentId },
        monitorExplicitlyUpdated: true,
      });
    } catch (err) {
      error = err;
    }
    expect(error).toMatchObject({
      status: 422,
      message: expect.stringContaining("send maxAttempts greater than 1"),
      details: { clearReason: "max_attempts_exhausted", attemptCount: 1, maxAttempts: 1 },
    });
  });

  it("explains how to re-arm a monitor whose timeout has passed", () => {
    const policy = normalizeIssueExecutionPolicy({
      stages: [],
      monitor: { nextCheckAt: "2099-04-11T12:30:00.000Z", timeoutAt: "2020-01-01T00:00:00Z", scheduledBy: "assignee" },
    })!;
    expect(() => buildInitialIssueMonitorFields({ policy, status: "in_review", assigneeAgentId: coderAgentId }))
      .toThrow(/Monitor bounds are already exhausted: timeoutAt 2020-01-01T00:00:00Z is not in the future/);
  });
});
