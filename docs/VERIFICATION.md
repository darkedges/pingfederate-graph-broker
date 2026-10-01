# Verification record

Verified on 23 September 2026 using Go 1.27.1 on Linux amd64.

| Check | Result |
|---|---|
| `go test -race -count=1 -cover ./...` | PASS |
| Broker package statement coverage | 80.1% |
| Top-level test functions | 11, plus table-driven subtests |
| `go vet ./...` | PASS |
| `go build -buildvcs=false -trimpath -o /tmp/graph-directory-broker ./cmd/broker` | PASS |
| Compiled binary starts with valid placeholder configuration | PASS |
| Health endpoint returns 200 and no-store | PASS |
| Protected endpoint without credentials returns 401 | PASS |
| SIGTERM graceful shutdown | PASS |
| Live PF 13.1 / Agentless Kit / Entra / Graph integration | NOT RUN — tenant configuration and credentials needed |
| Docker image / Compose execution | NOT RUN — Docker unavailable in build environment |
| GitHub Actions workflow | NOT RUN — source has not been pushed to a repository |

The initial build encountered the surrounding workspace's unavailable VCS metadata.
Source-archive builds now explicitly use `-buildvcs=false`; the subsequent build passed.
The tests use HTTP test servers inside the process. Production configuration requires
HTTPS for PF endpoints and fixes Microsoft endpoints to their public-cloud HTTPS origins.

The mock lifecycle test covers linking, immediate token redemption, delegation, user /
group / membership queries, pagination, cached reuse, forced expiry, refresh rotation
and disconnection. Security tests cover owner and client isolation, token-claim checks,
replay, scope escalation, concurrency, encryption, tamper detection and redirect safety.

This is evidence for the implemented starter's local behaviour, not certification of
your PF attribute mappings, your portal callback or your tenant's consent/CA behaviour.

## Local HTTPS portal callback — 24 September 2026

The separate `cmd/portal` browser handoff was tested with in-process TLS PF
and broker mocks. Its test covers OAuth state, PKCE code exchange, server-only
PF access-token handling, Connect CSRF, the Agentless form POST, origin rejection
and one-time Reference ID consumption. `go test -race -count=1 ./...`,
`go vet ./...`, and builds of both broker and portal passed in Linux Docker.
No live PF journey, Agentless adapter or Entra tenant was exercised.

## Make-driven portal environment — 25 September 2026

`make run-portal` now passes `.env` to the portal's PORTAL_-only loader. Parser
tests cover literal special characters, process-environment precedence and
malformed/duplicate settings. Repository-wide race tests, vet and broker/portal
builds passed in Linux Docker. A local Make invocation reached the portal and
correctly reported the currently blank `PORTAL_PF_CLIENT_SECRET`. With a
test-only secret and a separate loopback port, the HTTPS listener started.
The current workstation does not trust the generated mkcert CA (`PartialChain`),
so a validated browser/HTTP health check remains pending `mkcert -install`.

## Local interactive demo — 24 September 2026

The separate `compose.demo.yaml` stack built and started on Docker Desktop. Its
loopback health and portal state endpoints returned 200. HTTP smoke checks completed
connect, delegation, user and group reads, group members, cursor pagination, revoke
and disconnect. The new demo lifecycle and cross-origin tests passed with
`go test -race -count=1 ./...` in Linux Docker; `go vet ./...` and
`go build -buildvcs=false ./cmd/broker` also passed. No live identity tenant or
Microsoft Graph endpoint was contacted.
