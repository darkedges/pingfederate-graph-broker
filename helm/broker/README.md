# Kubernetes deployment

This chart deploys **only** the directory broker and the HTTPS portal. It does
not deploy or configure PingFederate, Entra ID, or Microsoft Graph. Configure
their externally reachable HTTPS URLs in a private values file. The portal and
broker share one pod so their internal call uses loopback; the broker's encrypted
store is on a persistent volume. The chart rejects replica counts other than
one and uses `Recreate` during updates. There is no distributed refresh lock or
shared portal session store.

## Prerequisites

- Push the `broker` and `portal` Docker image targets to a registry accessible
  by the cluster, then set `image.broker` and `image.portal` to immutable tags or
  digests. Run `make build-portal-ui` before building the portal image if you
  have edited `web/`.
- Have a persistent storage class and a DNS name and trusted TLS certificate
  for the portal. Register the exact public URL and callbacks with PF.
- Create a Kubernetes TLS Secret named by `portalTLSSecret` with `tls.crt` and
  `tls.key`. The portal terminates TLS itself; do not put the private key in
  Helm values or the image.
- Supply an existing Kubernetes Secret named by `existingSecret`, preferably
  through your secret manager. It must have these exact keys:

  `TOKEN_ENCRYPTION_KEY`, `PF_INTROSPECTION_CLIENT_SECRET`, `PF_PICKUP_USER`,
  `PF_PICKUP_PASSWORD`, `ENTRA_CLIENT_SECRET`, `PORTAL_PF_CLIENT_SECRET`,
  and `PORTAL_AGENT_CLIENT_SECRET`.

  Keep the encryption key stable and back it up separately from the PVC. It
  must decode to exactly 32 bytes. The portal and agent PF client secrets must
  match the configured PF clients. Do not commit a Secret manifest with values.
- If PF uses a private CA, create a Secret with the **public** PEM certificate
  as `ca.crt` and set `pfCASecret`. This augments the image's public roots; TLS
  verification remains enabled. The PF URL must be resolvable by both the
  browser and the pod, and its certificate must match the hostname.

## Install

Create a private values file containing the non-secret settings from
`values.yaml` for your environment. In particular set `broker.entraTenantID`,
`broker.entraClientID`, the PF HTTPS URLs and issuer, `broker.audience`,
`portal.publicURL`, `portal.pfURL`, `portal.connectStartURL`, image references,
and Secret names. Keep private values files out of version control.

```sh
helm lint helm/broker -f /path/to/private-values.yaml
helm template directory-broker helm/broker -f /path/to/private-values.yaml
helm upgrade --install directory-broker helm/broker \
  --namespace directory-broker --create-namespace \
  -f /path/to/private-values.yaml
```

The portal Service defaults to `ClusterIP` on port 443. Change
`portal.serviceType` to `LoadBalancer`, or use an ingress/gateway configured for
HTTPS upstream to the portal service. The browser-facing hostname and PF
registered callbacks must match `portal.publicURL`. The broker API binds only
to pod loopback by default and is **not** exposed by a Service. For agents in
other pods, enable `broker.service.enabled` only after putting the resulting
ClusterIP HTTP endpoint behind a reviewed mTLS service mesh or TLS reverse
proxy with restricted network access. Never expose bearer-token HTTP directly
to the internet. Agents still need their own PF token and exact delegation ID.

The portal `/healthz` and broker `/healthz` endpoints back the readiness and
liveness probes. A successful probe does not validate live PF, Entra, or Graph
connectivity. Test sign-in, link, grant, read, revoke, and disconnect after
installation. A pod restart clears portal sessions and in-memory delegation
selection; saved broker connections remain on the PVC. Re-grant agent access as
needed. Back up the PVC and encryption key separately.
