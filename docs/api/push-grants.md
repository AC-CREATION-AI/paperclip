---
title: Push grants
summary: Bounded, human-approved git publication by the server
---

Push grants let the server publish **one** exact commit to **one** branch on behalf of an agent run, after a human agreement. There is no other publication path: without a grant, nothing is pushed. The feature is not enabled for any adapter yet (no `push_grant` runtime capability is minted by the runtime).

Both routes require a runtime-tools token with scope `push_grant`, bound to a live run that owns its task.

## Issue a grant

```
POST /api/companies/{companyId}/push-grants
{
  "issueId": "...", "interactionId": "...", "requestId": "...",
  "forge": "github", "repository": "owner/name", "ref": "refs/heads/feature",
  "mode": "force-with-lease" | "fast-forward",
  "expectedOldSha": "<40 hex>", "newSha": "<40 hex>", "ttlSeconds": 120
}
```

A grant lives at most 120 seconds.

## Consume a grant

```
POST /api/companies/{companyId}/push-grants/{grantId}/consume
{ "requestId": "...", "repository": "...", "ref": "...", "expectedOldSha": "...", "newSha": "..." }
```

A replay with the same `requestId` returns the stored result only to the same grant, agent and run. Any other caller gets `409`.

## Human agreement format

`interactionId` must reference an accepted, human-only `request_confirmation` on the task or one of its ancestors. Its `detailsMarkdown` must be **only** this JSON object (pretty-printing allowed):

```json
{"kind":"push_grant","repository":"owner/name","ref":"refs/heads/feature","mode":"force-with-lease","expectedOldSha":"<40 hex>","newSha":"<40 hex>"}
```

- No extra or missing field, no duplicated key, and no prose around the block.
- The prompt, the details and the human answer together must contain exactly one block.
- The block must match the request exactly. Repository and SHAs are compared case-insensitively, and the ref and mode must match exactly.
- One agreement opens one grant. The agreement can be used again only if that grant ended as `failed`, `expired`, `revoked` or `rejected`. A grant that is `issued`, `consumed` or `unknown` blocks the agreement. The database enforces this with the partial unique index `push_grants_active_interaction_uq`.

## Repository allowlist

The server reads the allowlist from the table **`push_grant_repositories`**, with columns `company_id`, `forge` and `repository`. Repository matching is case-insensitive. A repository that is not listed for the company is refused with `422 repository_not_allowed`, both when the grant is issued and when it is consumed. There is no API to write to this list: an operator adds the rows when the feature is enabled.

## Default branches

On `refs/heads/main`, `refs/heads/master` and `refs/heads/trunk`, only `fast-forward` is accepted. A `force-with-lease` request is refused with `422 protected_ref`.

## Push source

The server fetches the commit from the run workspace (`paperclipWorkspace.cwd`). The consumption fails with `source_unavailable` when any of these is true:

- the real path is outside the instance roots `isolated-workspaces`, `projects` or `workspaces`;
- `.git` is not a directory;
- `.git/objects/info/alternates` exists.
