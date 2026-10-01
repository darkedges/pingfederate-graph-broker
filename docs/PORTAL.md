# Local HTTPS portal callback

`cmd/portal` is a small, separate local backend for the live PF browser journey.
It is not the self-contained simulator on port 8097. It keeps the PF user access
token in server memory and places only an opaque, Secure, HttpOnly session cookie
in the browser. It does not return tokens or Reference IDs in its pages.
The main page is a Next.js single-page interface, statically exported from `web/`
and embedded in the Go portal. The Go backend remains the same-origin authority
for sign-in, callbacks, sessions, connection actions, and Graph reads; a Next.js
server is not needed at runtime. The previous basic page remains at `/legacy`.

## Configure

Create a browser-trusted certificate for `localhost` and `127.0.0.1`. For example,
with `mkcert` installed:

```powershell
mkcert -install
New-Item -ItemType Directory -Force certs
mkcert -cert-file certs/portal.pem -key-file certs/portal-key.pem localhost 127.0.0.1
```

The `certs/` directory is ignored by Git. Do not commit the key. The PF runtime
certificate must also be trusted by this Go process; do not bypass TLS checks.
For the local PF container, the same mkcert pair can be imported and activated
on PF's admin and runtime listeners by the opt-in
[Terraform local TLS configuration](../terraform/README.md#local-pingfederate-https-certificate).
Prepare its password-protected PKCS#12 bundle from the same pair before enabling
the Terraform import; PF rejects the raw unencrypted mkcert PEM key.
The read-only Compose mount alone does not change PF's presented certificate.
The portal runs on the **host** so both the browser and portal can use
`https://localhost:9031` for PF, and the portal can reach the broker at its
loopback port. For the broker container, add mkcert's public root CA to
`certs/ca/mkcert-rootCA.pem` as described in the
[Terraform local handoff guide](../terraform/README.md#development-only-entra-handoff);
never give the broker the portal key or disable certificate verification.
Add these `PORTAL_` settings to the ignored repository `.env`
(the tracked `.env.example` contains the template):

| Variable | Local value |
|---|---|
| `PORTAL_PUBLIC_URL` | `https://localhost:8788` |
| `PORTAL_LISTEN_ADDR` | `127.0.0.1:8788` |
| `PORTAL_TLS_CERT_FILE` | Absolute or repo-relative path to `certs/portal.pem` |
| `PORTAL_TLS_KEY_FILE` | Absolute or repo-relative path to `certs/portal-key.pem` |
| `PORTAL_PF_URL` | `https://localhost:9031` |
| `PORTAL_PF_BROWSER_URL` | Optional browser-facing PF runtime origin; defaults to `PORTAL_PF_URL`. Use `https://ping.entraid.darkedges.com` for the tunnel while keeping backend token exchange local. |
| `PORTAL_PF_CLIENT_ID` | `directory-portal` |
| `PORTAL_PF_CLIENT_SECRET` | Same secret supplied to the PF portal OAuth client; deliver privately |
| `PORTAL_AGENT_CLIENT_ID` | `directory-agent` for live delegated reads |
| `PORTAL_AGENT_CLIENT_SECRET` | Same secret supplied to Terraform for the PF agent OAuth client; deliver privately |
| `PORTAL_BROKER_URL` | `http://127.0.0.1:18082` (local broker profile only) |
| `PORTAL_PF_CONNECT_START_URL` | The fixed HTTPS PF SSO initiation URL for your reviewed Entra → Reference ID SP journey |
| `PORTAL_REFERENCE_SUBJECT` | Exact broker-verified PF `sub` allowed to start and complete the Reference ID journey; here `broker-dev-user` |
| `PORTAL_SAML_SUBJECT` | Exact broker-verified PF `sub` allowed to start SAML exchange; here `nirving@ping.darkedges.com` |

Set `PORTAL_PF_CLIENT_SECRET` and `PORTAL_AGENT_CLIENT_SECRET` to the same
respective private values supplied to Terraform for the portal and agent PF
OAuth clients. The two `PORTAL_AGENT_` values must be set together; without
them, sign-in and Connect work but agent delegation and reads are unavailable.
Leave `PORTAL_PF_CONNECT_START_URL` empty
until the PF journey exists; a blank client secret prevents startup.
Once the reviewed `pf_handoff` is applied, Terraform outputs a
`portal_connect_start_url_candidate` using the managed IdP connection and SP
adapter IDs. Verify that URL against PF's Summary & Activation page and SP
authentication policy before copying it to `.env`; a configured URL alone
does not make an incomplete handoff work. Restart the portal to load the new
value. The broker must also be running and healthy before Connect can create
a link intent.
Then, from the repository root, run:

```powershell
make run-portal
```

This target starts `go run ./cmd/portal -env-file .env`. The portal loads only
`PORTAL_` keys; explicit process environment values take precedence. The file
is parsed as literal `KEY=value` lines, not as shell code. Do not append inline
comments to portal values. No secret is placed on the command line. Open
`https://localhost:8788`. The portal does not start the broker or PF for you.
Its readiness path is `https://localhost:8788/healthz`. A missing Connect
start URL permits PF sign-in but disables the Connect action.

To change the interface, install Node.js and pnpm, then run `make build-portal-ui`
from the repository root. This installs the pinned frontend dependencies, builds
the static export, and copies it into `cmd/portal/ui/` for Go embedding. Restart
`make run-portal` afterward; an already-running portal will continue serving its
previous embedded build. Restarting clears in-memory sign-in and delegation state,
so sign in and grant access again. Saved broker connections are not deleted.

For a local Reference ID handoff diagnosis, set `PORTAL_LOG_LEVEL=debug` in
the ignored `.env` and restart the portal. Structured events show when an
intent is created, whether the Form POST reached `/auth/reference-callback`,
which fixed check rejected it, and whether the broker completion succeeded.
They never include `REF`, OAuth codes, bearer tokens, cookies, raw query
strings, upstream response bodies, or raw transport errors. Set the level back
to `info` afterward. If PingFederate displays an error before the Form POST,
the portal will have no `reference_callback_received` event; inspect PF's
server and audit logs for that attempt instead.

A `reference_callback_rejected` event reports a fixed reason such as
`reference_missing`, `reference_duplicate`, `reference_empty`,
`reference_oversized`, `target_resource_mismatch`, or
`unexpected_form_fields`, plus the number of form
fields. Do not copy or log the submitted form, reference value, or callback
URL when reporting a failure.

In Terraform, use `portal_redirect_uri = "https://localhost:8788/auth/callback"`.
This is a change from the earlier HTTP port 8787 value: review the identity plan
and apply it to update the **disabled** portal client before activation. Configure
the Agentless Reference ID SP Adapter separately with target application URL
`https://localhost:8788/auth/reference-callback`, Transport Mode **Form POST**,
and TLS required. The browser must trust the portal certificate for that POST.
The OAuth code callback and Reference ID callback are different endpoints.

The PF OAuth client must be active, allow authorization code with PKCE and
`broker.connect`, and issue a user token that passes the broker's strict
introspection contract. The broker must be reachable and configured to use
the actual PF pickup endpoint. The Entra OIDC IdP connection, validated
attribute mapping, Agentless adapter and PF SSO initiation route are not
created merely by starting this portal. Follow [PINGFEDERATE.md](PINGFEDERATE.md)
and [the Terraform guide](../terraform/README.md) before attempting a live link.

## Flow and limitations

1. Sign in through PF authorization code + PKCE. The portal checks OAuth state
   and exchanges the code from its backend. No PF token enters browser storage.
2. Connect creates a five-minute broker link intent with the user's token. Its
   form POST ends on a same-origin continuation page, which then navigates to
   the fixed PF journey URL. This avoids browsers treating the PF redirect as
   a forbidden `form-action 'self'` target. A visible Continue link is available
   if automatic navigation is disabled.
3. The Agentless form POST supplies `REF` and `TargetResource`. The portal
   accepts `TargetResource` only when it exactly matches its configured reference
   callback URL; it never redirects to that submitted value. The portal also
   requires its session cookie, the PF `Origin`, and an unexpired one-use
   intent. It consumes that intent once, then submits the reference to the broker
   with the same user's token in a bounded background request. The broker checks
   subject ownership and performs authenticated pickup. The portal shows an indeterminate progress
   bar while this completes; it does not claim a percentage from PF or Graph.

If you return to the portal before PF finishes, it shows the pending request
and a **Continue Microsoft sign-in** link instead of starting a second intent.
An abandoned intent clears when its broker-issued expiry is reached, after
which **Connect Microsoft** becomes available again. A failed completion shows
a retry message. The reference and PF access token remain server-side.

The Connect panel offers two selectable paths. **Existing connection** is the
working PingFederate Reference ID journey above. **SAML token exchange** calls
the broker through the portal backend only when `PORTAL_SAML_CONNECT_ENABLED=true`.
The broker enables `POST /v1/connections/saml` only when `SAML_ENABLED=true`
and all `SAML_*` settings in `.env.example` are supplied. Partial settings
are inert while the flag is false. It exchanges the already-introspected
portal PF access token for a SAML 1.1 assertion, then for an Entra custom-API
token, then performs Entra OBO to obtain a read-only Graph token.
The OBO request uses `https://graph.microsoft.com/.default`, as required by
Entra; the broker still rejects a returned Graph token unless it has both
required read scopes and no unapproved scopes or write permissions. It checks
the Entra tenant and immutable object ID at both token stages. The resulting
connection is session-limited: no refresh token is expected, no refresh is
attempted, and delegations cannot outlive its Graph token.

**The current localhost PF is not yet provisioned for this exchange.** Its
portal access token is a *reference* token. A dedicated PF subject-token
processor/policy must accept that token type, validate the authenticated
subject, and issue a signed SAML 1.1 assertion trusted by the target Entra
tenant. The existing remote `TEST` policy instead accepts a JWT and has
literal identity mappings; do not point this portal at it or copy that mapping.
The Entra OBO app must have only `User.ReadBasic.All` and
`GroupMember.Read.All` delegated Graph consent. The demonstrated app's Graph
token contains a write permission, so it must not be used unchanged. The
broker's one-user allowlist needs the exact PF subject and Entra object ID;
email is never used to search for or link an account. See
[EXISTING_SAML_EXCHANGE.md](EXISTING_SAML_EXCHANGE.md).

The session is in memory. Restarting the portal or expiring the PF access token
requires a new sign-in. A failed callback consumes the intent; press Connect
again. **Manage connections and directory reads** lists the signed-in user's
saved broker connections, lets the user grant selected read-only operations to
the configured agent for one hour, displays the first page of users, groups, or
direct members of a specified group,
and offers revoke and disconnect actions. The Next.js interface supports the
broker's opaque cursor pagination for users, groups, and direct members. The
portal backend obtains the agent's PF client-credentials token for each read;
neither PF nor Entra tokens enter the browser. A portal restart loses the
in-memory delegation ID, but disconnecting the saved connection revokes its
delegations. Signing out alone does not revoke anything.
