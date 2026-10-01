# Broker API examples

All URLs below use a localhost development binding. Use HTTPS in remote environments.
`PF_USER_TOKEN` is a user access token issued to the portal; `PF_AGENT_TOKEN` is an
agent access token. Neither is a Microsoft Graph token. Examples assume these values
are already supplied securely to your shell. Avoid printing responses from OAuth token
endpoints or putting tokens in shell history.

## Connect

```sh
curl --fail-with-body -X POST http://127.0.0.1:8080/v1/link-intents \
  -H "Authorization: Bearer ${PF_USER_TOKEN}"
```

Response:

```json
{"intent_id":"<intent-id>","expires_at":"2026-09-23T12:05:00Z"}
```

Now complete the PF browser connection flow through your portal. The portal receives
a short-lived Reference ID. Its backend immediately submits:

```http
POST /v1/link-intents/{intent-id}/complete
Authorization: Bearer <same user's PF token>
Content-Type: application/json

{"reference":"<PF Reference ID>"}
```

The response includes `connection_id`, `tenant_id`, `object_id`, `status`, `scopes` and
`created_at`. It never includes tokens. The broker validates the refresh token during
this step, so a wrong Entra client registration fails before the connection is saved.

## Delegate reads to an agent

This is an explicit user-authorised portal action. Choose a lifetime from 60 seconds
to 604800 seconds (seven days), then create the delegation with the owner's user token:

```http
POST /v1/connections/{connection-id}/delegations
Authorization: Bearer <owner's PF token>
Content-Type: application/json

{
  "agent_client_id":"directory-agent",
  "operations":[
    "directory.find_users",
    "directory.find_groups",
    "directory.list_group_members"
  ],
  "expires_in_seconds":86400
}
```

Response:

```json
{
  "delegation_id":"<opaque-delegation-id>",
  "expires_at":"2026-09-24T12:00:00Z",
  "operations":["directory.find_users","directory.find_groups","directory.list_group_members"]
}
```

Only the listed agent client can use this delegation. The owner can delegate fewer
operations. Delegation IDs are not credentials and are insufficient without the right
PF access token. Each agent should have its own PF OAuth client. This version's directory
reads cover the data available to the underlying user; per-object target restrictions
and administrative-unit policy are not implemented.

## Query directory data

```sh
curl --fail-with-body --get \
  "http://127.0.0.1:8080/v1/delegations/${DELEGATION_ID}/users" \
  -H "Authorization: Bearer ${PF_AGENT_TOKEN}" \
  --data-urlencode 'prefix=Nick'
```

Replace `/users` with `/groups` to search groups. The prefix matches `displayName`.
For direct members of a known group:

```http
GET /v1/delegations/{delegation-id}/groups/{group-guid}/members
Authorization: Bearer <agent PF token>
```

Response:

```json
{
  "items":[
    {"id":"<user-id>","displayName":"Nicholas Example","mail":"nicholas@example.com","userPrincipalName":"nicholas@example.com"}
  ],
  "next_cursor":"<opaque-cursor-if-more-results>"
}
```

Members are not recursively expanded. Member DTOs can include `@odata.type` and may
contain only an ID where Graph cannot disclose other properties. To continue, use
the same route with `?cursor=<URL-encoded-next_cursor>`, without `prefix`. The broker
validates the cursor, uses its fixed Graph origin/path and performs another authorisation
check. It returns one Graph page per request, with a requested size of 25. No generic
Graph URL, arbitrary `$filter` or raw Graph continuation link is exposed.

## Inspect, revoke and disconnect

```http
GET /v1/connections
Authorization: Bearer <owner PF token>
```

```http
DELETE /v1/delegations/{delegation-id}
Authorization: Bearer <owner PF token>
```

```http
DELETE /v1/connections/{connection-id}
Authorization: Bearer <owner PF token>
```

DELETE returns 204 on success. A connection deletion removes every associated delegation
and token from current state. An already-running read can complete before revocation
returns; after a successful revocation response no new read is authorised by that record.
Encrypted backups can retain old versions; handle backup retention separately.

## Error handling

Errors have a stable JSON envelope, for example `{"error":"reconnect_required"}`.
The broker does not relay provider error bodies or claims challenges to the agent.

| HTTP | Example code | Agent/portal action |
|---|---|---|
| 400 | `invalid_cursor`, `unsupported_query_parameter` | Fix the request; restart pagination for an expired cursor |
| 401 | `invalid_token` | Obtain a new PF access token |
| 403 | `operation_not_delegated`, `graph_access_denied` | Stop; investigate policy/underlying user permission |
| 404 | `delegation_not_found` | Wrong agent, expired/revoked delegation or unknown ID |
| 409 | `reconnect_required` | Pause job; user reconnects and delegates the new connection |
| 409 | `unexpected_entra_permissions` | Correct upstream scope configuration; do not broaden automatically |
| 429 | `graph_throttled` | Wait at least the conservative 30-second Retry-After and apply jitter |
| 502 | `entra_refresh_failed`, `pickup_failed` | Operator investigates credentials/mapping; never log raw token payloads |
| 503 | `identity_service_unavailable`, `entra_temporarily_unavailable` | Bounded retry with exponential backoff |

All responses have `Cache-Control: no-store`. Authentication failures fail closed.
Network requests have timeouts, bounded response bodies and disabled redirects.

## Example agent tool contract

Wrap these routes in your agent's normal tool interface. Keep PF credentials and tokens
in the tool-execution backend, not model arguments. A suitable model-visible tool is:

```json
{
  "name":"directory_find_users",
  "description":"Find directory users by display-name prefix using an authorised connection.",
  "parameters":{
    "type":"object",
    "properties":{"prefix":{"type":"string","maxLength":100}},
    "required":["prefix"],
    "additionalProperties":false
  }
}
```

The tool backend supplies the delegation ID from the authorised job context and its PF
token from secure storage. It must not let model arguments choose arbitrary connections
or HTTP destinations. The broker returns data only. This project is an HTTP service;
an MCP transport wrapper is not included.
