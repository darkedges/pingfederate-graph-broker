# Operational boundaries and acceptance

## Implemented controls

- All protected requests are introspected against a configured HTTPS PF endpoint.
- Exact issuer/audience, expiry, optional not-before, Bearer type, fixed principal-kind,
  scope and client allowlists are enforced. Missing claims fail closed.
- Link intents are one-use, owner-bound and expire in five minutes. Starting a new one
  cancels an earlier pending intent for that user. Completion consumes it before pickup.
- The PF pickup subject must equal the authenticated portal subject. Tenant and object
  claims come from the authenticated PF handoff, not from a client JSON token import.
- Graph scopes are constrained. The initial upstream access token is replaced through
  the configured client's refresh exchange before the connection is accepted.
- Delegations bind owner, connection, agent client, operations and expiry. User endpoints
  cannot be called with agent credentials. Agent reads cannot use a user's management token.
- All persistent state uses AES-256-GCM with random nonces and version-specific associated
  data. New files are private; writes use temporary files, fsync and atomic rename.
- A data-directory lock prevents a second process. A failed directory fsync poisons the
  store until restart rather than continuing with uncertain state.
- Refreshes are serialized per connection using bounded striped locks. A lock can also
  serialize unrelated connections with the same stripe; this is a starter tradeoff.
- Revocation obtains the same connection lock, so it does not race a refresh and restore
  a deleted token. Graph read completion happens before a conflicting revoke returns.
- Output DTOs strip unrequested provider fields. Cursors are encrypted/authenticated,
  expire and bind to a delegation and exact path. All outbound redirects are disabled.
- Audit events contain caller client ID, operation category, outcome and delegation ID;
  no tokens, bodies, references, search strings or raw upstream errors are logged.

For local handoff diagnosis, `PORTAL_LOG_LEVEL=debug` enables portal callback
stage and rejection-reason events. `BROKER_LOG_LEVEL=debug` enables pickup
stage and HTTP-status events; changing the broker container's `.env` requires
a controlled container restart through the managed runtime. These diagnostic
events omit reference IDs, tokens, payloads, URLs and raw transport errors.
Return both levels to `info` after diagnosis.

## Deliberate limits

The complete state file is re-encrypted for every mutation. This is suitable for a small
proof of concept, not high-volume deployments. Single-tenant Microsoft public-cloud
endpoints are fixed in environment loading. Sovereign clouds and multi-tenant lookup
are not implemented. Storage uses Unix flock and is not a native Windows implementation.

The broker trusts the configured PF issuer, its attribute mapping and the portal's
server-side user/session handling. A misconfigured PF client that can mint arbitrary
user authority can compromise the connection store. The broker cannot repair that
upstream trust failure. Do not make `sub`, principal-kind or the account-link subject
user-controlled. The portal callback's anti-CSRF binding remains the portal's responsibility.

The service has no generic admin API, full production browser UI, MFA/step-up engine,
MCP transport, complete PF handoff Terraform provisioning, certificate-based Entra client authentication, KMS integration,
distributed storage/locking, automatic key rotation or per-object authorisation policy.
Read scopes can still expose organisation-wide data available to the delegated user.

The encrypted file is protected against tampering, but a privileged filesystem operator
can restore an older valid backup (rollback). Host compromise can also expose in-memory
tokens and the process encryption key. Use a managed secret store and audited database
with transactional concurrency before production. Do not replace encryption keys without
an explicit migration; the current code has no multi-key rotation mechanism.

The service binds to loopback by default and relies on a TLS reverse proxy for remote
clients. Set ingress rate limits, connection/body limits, caller quotas and egress rules.
Only permit necessary PF endpoints, Entra's configured token endpoint and Graph. Protect
proxy logs from query strings, headers and reference values. The starter does not implement
application-level rate limiting. Docker's startup can fail if a bind-mounted data directory
is not owned/writable by UID 65532; provision volume ownership rather than running as root.

Graph 403 does not cause endless token refresh. Graph 401 causes reconnection instead of
attempting to bypass a claims challenge. Users can still be required to reauthenticate
because of Conditional Access or revocation. The connector never converts a PF-issued
token directly into a Microsoft token; it redeems a legitimately acquired Entra grant.

Disconnect stops this broker and erases current tokens; it does not revoke all user
sessions or remove Entra consent. Perform Entra-side revocation separately if required.
Retain broker audit logs with delegation metadata in your operational system so an
Entra app/user call can be correlated to the particular agent job.

## Local verification

`go test -race -count=1 ./...` covers mock linking, forced initial refresh, rotation,
cached reuse, parallel requests, owner/agent isolation, expired delegation, missing and
invalid token claims, callback mismatch/replay, scope escalation, invalid grants,
provider failures, no-write routing, pagination constraints, OData string escaping,
encrypted disk persistence, tamper detection and credential-bearing redirects.

## Live acceptance checklist

1. Confirm the exact PF 13.1 patch and supported Agentless Kit version.
2. Configure an isolated Entra app and least-required delegated scopes; obtain consent.
3. Inspect only the **shape** of the pickup payload in a controlled test. Confirm the
   full token response is available, correctly serialized and masked in all logs.
4. Verify `subject` matches the portal access token's canonical `sub`. Test another
   user/browser transaction to confirm a cross-account link is rejected.
5. Confirm introspection returns the required claims for portal and agent tokens.
6. Connect a test user, delegate to a test agent and call all three read endpoints.
7. After initial access-token expiry, verify renewal works with the browser closed.
8. Test grant revocation/Conditional Access and confirm `reconnect_required` reaches the
   portal workflow. Do not silently fall back to application permissions.
9. Revoke a delegation and disconnect a connection; check subsequent agent reads fail.
10. Restart the broker with its persistent volume and key; confirm authorised reads resume.
11. Confirm API, reverse-proxy, PF and audit logs contain no credentials or token payloads.

## Next production milestone

Replace the file store with PostgreSQL transactions and a per-connection advisory lock;
add managed key encryption, explicit per-object policy where required, operational metrics,
rate limiting and an integration test against a non-production PF/Entra environment.
Preserve the current behavioural tests when replacing persistence.
