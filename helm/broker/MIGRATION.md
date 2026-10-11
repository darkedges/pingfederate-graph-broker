# DarkEdges single-instance cutover

Target namespace: `entraidbroker`. This is a migration plan, not an executed
cutover. Keep the Docker source and a recoverable backup until acceptance.

Confirmed: context `docker-desktop`, ingress class `nginx`, ClusterIssuer
`vault-issuer`, public Docker Hub images, cluster-default storage, and migration
of the existing encrypted state. The user reports pods can reach public PF.
Images: `docker.io/darkedges/entraid-broker:v0.01` and
`docker.io/darkedges/entraid-portal:v0.01`. Verify these images include the
new broker healthcheck option before installation. The Vault-issued
certificate's CA bundle remains to be supplied. A maintenance-window shutdown
has not been scheduled.

Use explicit `--kube-context docker-desktop` on Helm commands and
`--context docker-desktop` on kubectl commands rather than changing the global
current context. Vault-issued public-facing certificates must be trusted by
browser clients as well as by NGINX when it validates the portal upstream.

## Existing Cloudflare route ownership

Read-only review of `E:/development/projects/cloudflare/cloudflare-ssl/tunnel.tf`
found `local.entraid_ingress` currently routes portal to
`https://127.0.0.1:8788`, broker to `http://127.0.0.1:18082`, and PF to
`https://127.0.0.1:9031`. The portal/PF routes currently disable upstream TLS
verification. These are current-state observations, not recommended settings.

The same repository has a separate Kubernetes tunnel routing other hosts to
`https://ingress-nginx-controller.ingress-nginx:443`. Cutover must migrate
portal/broker DNS ownership and ingress routes together, preserving all unrelated
rules and the terminal catch-all. Keep PF on its existing external route.
Do not simply add duplicate DNS resources for the same names in both tunnels.
Use explicit origin SNI/hostname and trust the Vault CA in cloudflared; do not
copy the existing `no_tls_verify=true` shortcut into the migrated routes.
The tunnel repository has not been edited or applied by this preparation.

## Preparation (source remains running)

1. Confirm kubeconfig context, ingress class, exact ClusterIssuer, full image
   paths/digests and pull Secret. Copy `values-darkedges.example.yaml` to a
   private values file and replace placeholders. Its non-secret identity
   settings reflect the local environment at preparation time; verify them.
2. Verify PF can be reached from the cluster at its public hostname. Keep the
   issuer set to the exact value in existing token mappings, independently of
   the reachable PF URL. Check that Cloudflare policies allow PF backchannel
   introspection, token and pickup calls without interactive challenges.
3. Prepare the credentials Secret without printing it or committing it. Use
   the **existing** `TOKEN_ENCRYPTION_KEY`; do not generate a new key. Include
   the base and enabled SAML/inbound credentials listed in the chart README.
4. Have cert-manager issue the portal TLS Secret in `entraidbroker` before
   starting the portal. The Ingress can exist before its Service. Alternatively
   preissue a Certificate with the same DNS name/Secret. Certificate issuance
   must be complete before the pod can mount the TLS Secret.
5. Supply `portal-upstream-ca` containing the public CA bundle as `ca.crt` for
   NGINX upstream verification. The example reuses the issued portal
   certificate for edge and pod TLS and checks the public DNS name via SNI.
6. Provision the target PVC using the cluster default StorageClass. Do not
   start the application against an empty store before copying the source.
   Broker ingress remains disabled pending a reviewed NetworkPolicy or mesh
   for its HTTP upstream. Namespace separation alone is not isolation.

## Maintenance window (explicitly scheduled)

1. Stop the source broker cleanly; identify its exact Docker volume/mount via
   read-only inspection. Never delete or empty it. Refresh-token rotation means
   copying a running store and continuing to run both instances is unsafe.
2. Back up the stopped `state.enc` and preserve the matching encryption key
   separately. Compare source/target hashes after transfer. Do not print file
   contents or key material. Copy the encrypted state only; do not copy a live
   process lock. Do not place a backup inside the container image.
3. Mount the destination PVC in a temporary, approved migration pod while the
   application is stopped. Restore `state.enc` with access restricted to the
   application's UID/GID 65532; then remove the migration pod before startup.
4. Install the chart using the prepared PVC/Secret names and immutable images.
   Never run source and target brokers concurrently against copies of the same
   refresh tokens. Switch the portal/broker DNS or tunnel routes deliberately.
5. Verify health, PF sign-in/logout, saved connection metadata, Reference ID
   and SAML paths, delegation, a read-only directory request, and revocation.
   Portal sessions are in memory and do not migrate; users must sign in again.

## Rollback

Stop the Kubernetes broker before restarting Docker. If Kubernetes has redeemed
refresh tokens, its newer encrypted state is authoritative: export it while
stopped and restore it to the source with the same key before rollback. Never
blindly restart an old backup after rotation. Keep both backups recoverable and
do not remove the old volume or PVC as part of this procedure.
