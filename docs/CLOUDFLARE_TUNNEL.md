# Cloudflare Tunnel hostnames

The tunnel routes public hostnames to local origins; do not change Docker's
loopback-only published ports when `cloudflared` runs on the same host.

| Public hostname | Local service URL on the tunnel host |
| --- | --- |
| `portal.entraid.darkedges.com` | `https://localhost:8788` for `make run-portal`, or `https://localhost:18788` for the current Compose portal |
| `broker.entraid.darkedges.com` | `http://127.0.0.1:18082` for the current Compose broker |

The portal origin uses an mkcert localhost certificate. Configure cloudflared
to trust its issuing CA (or install that CA into cloudflared's trust store),
keep TLS verification enabled, and use `localhost` as the origin server name.
Do not point a service URL at its own public tunnel hostname. The broker origin
is loopback HTTP because the tunnel connector is on the same host; the public
side is HTTPS. If cloudflared runs elsewhere, these loopback URLs are invalid:
put an authenticated, TLS-protected private route in front of the origins
instead of exposing port 18082 on the LAN without controls.

Add a third tunnel route:

| Public hostname | Local service URL on the tunnel host |
| --- | --- |
| `ping.entraid.darkedges.com` | `https://localhost:9031` (PF runtime only; never tunnel the admin port 9999) |

PF serves a localhost mkcert certificate. Configure cloudflared to trust its
issuing CA, keep TLS verification enabled, and use `localhost` as the origin
server name. Make sure browser-visible PF redirects stay on the public PF
hostname. The separate [`terraform/virtual-hosts`](../terraform/virtual-hosts/README.md)
state adopts PF's existing virtual-host list and adds that hostname without
changing the base URL or OAuth issuer; this keeps PF-hosted CSS and other
assets on the same browser origin.

Before using the public portal, set
`PORTAL_PF_BROWSER_URL=https://ping.entraid.darkedges.com` for authorization
redirects. Keep `PORTAL_PF_URL=https://localhost:9031` for the portal backend's
code exchange; keep broker-to-PF introspection/pickup private as well. Do not
set the browser URL to the PF admin endpoint.

The portal's public URL must be exactly
`PORTAL_PUBLIC_URL=https://portal.entraid.darkedges.com`. Its OAuth callback
then becomes `https://portal.entraid.darkedges.com/auth/callback`. Terraform's
`portal_additional_redirect_uri` stages this as a second PingFederate OAuth
redirect while preserving the localhost callback. Apply the reviewed PF client
plan before switching `PORTAL_PUBLIC_URL`, then restart the portal. Do not
turn off origin/CSRF checks to make redirects pass.

For the one-user Reference ID development handoff, set
`pf_dev_reference_callback_url=https://portal.entraid.darkedges.com/auth/reference-callback`
and apply the PingFederate Terraform change before using the browser journey.
The Agentless adapter's Authentication Endpoint and Entra connection's default
target URL must both be this exact public URL. Set
`PORTAL_PF_CONNECT_START_URL` to the reviewed `portal_connect_start_url_candidate`
with its origin changed from `https://localhost:9031` to
`https://ping.entraid.darkedges.com`; keep the path and encoded partner ID.
The portal accepts the form POST only from the configured public PF browser
origin. The SAML connection path does not use this handoff. The dev-only PF
login and one-user handoff are not production identity sources.

PingFederate's OIDC connection to Entra can generate its `/sp/.../cb.openid`
callback on the public `ping.entraid.darkedges.com` hostname during this
journey. Set `pf_oidc_public_redirect_uri` to the exact URI from the Entra
`AADSTS50011` error and apply Terraform. The Entra connector app then keeps
both that public URI and the PF-computed local URI. Do not substitute the
portal's `/auth/callback` or Reference ID callback for this OIDC callback.

The broker has no public URL setting: keep `PORTAL_BROKER_URL` on loopback so
the portal talks to it privately. A public broker API should be protected by
Cloudflare Access or an equivalent client policy. Its PF bearer-token checks
and per-agent delegation checks remain mandatory; a tunnel is not a substitute
for them. Do not expose Terraform state, the PF admin port, or `.env`.
