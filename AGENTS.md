# Repository instructions

This is a Go broker for PingFederate 13.1 and Microsoft Graph delegated directory reads.

- Keep Graph permissions read-only. Do not add Directory.ReadWrite.All or generic Graph proxying.
- Entra access/refresh tokens stay inside the broker. Never add a public token-returning endpoint.
- Authenticate with PF introspection; require issuer, audience, expiry, bearer token type,
  client allowlist, scope and broker_principal_type. Do not weaken these to make a demo pass.
- Link connections by the canonical authenticated subject, never by an email match.
- Validate an active delegation bound to the exact agent client on every Graph request.
- No network calls from encrypted store callbacks. Serialize refreshes using the connection lock.
- Persist refresh replacements before using their access token. Preserve an existing refresh
  token if Entra omits a replacement. Fail closed on invalid_grant and scope escalation.
- Cursor URLs must be authenticated, bound to the delegation and route, and restricted to
  the configured Graph origin and exact path. Never follow redirects with credentials.
- Never log upstream response bodies, access/refresh tokens, reference IDs, query strings or secrets.
- Run go test -race -count=1 ./..., go vet ./..., and go build -buildvcs=false ./cmd/broker after meaningful changes.
- Tests must use local mocks; do not change real tenant configuration or call live Graph writes.
- The store is single-instance Linux/macOS storage. A database migration must include
  distributed refresh locking and atomic rotation before supporting multiple replicas.
- Read docs/PINGFEDERATE.md before changing the attribute contract or browser handoff.
