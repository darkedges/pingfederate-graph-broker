# Live PingFederate + Entra Terraform

This directory manages a dedicated Entra app, its two **delegated read-only**
Microsoft Graph permissions, two PingFederate reference-token managers and
their mappings, a portal OIDC policy, three PF clients, an optional dev-only
portal login source, and (when explicitly configured) an Entra OIDC IdP
connection plus Reference ID SP adapter. The
separate [`runtime`](runtime/main.tf) state manages the existing Compose stack;
[`scopes`](scopes/main.tf) adopts PF's global OAuth settings.
It is a scaffold for a live integration, not evidence that this tenant has been
connected or that the security-critical PF attribute flow has been tested.

## Values for this local environment

The ignored `terraform.tfvars` supplies non-secret Terraform inputs; Terraform
does not read the broker's `.env`. Its tracked template is
[`terraform.tfvars.example`](terraform.tfvars.example). It includes your tenant ID `224fe641-9036-4262-9a10-281a65cdbf6e`,
PF runtime `https://localhost:9031`, and portal OAuth callback
`https://localhost:8788/auth/callback`. The PF administration endpoint is
assumed to be `https://localhost:9999`; confirm it in your container. Choose a
broker audience URI and keep it *identical* in Terraform, `.env`, and the
introspection response. The PF issuer must also match the broker's `PF_ISSUER`
exactly; a trailing slash matters.

The local HTTPS portal has two different paths: the PF OAuth code redirect is
`/auth/callback`, while the Agentless Reference ID Form POST target is
`https://localhost:8788/auth/reference-callback`. See
[`docs/PORTAL.md`](../docs/PORTAL.md). The in-process demo on port 8097 remains
simulated; the new local portal is a separate process.

## Before applying

1. Obtain a licensed PingFederate image, an admin account for its management
   API, and a trusted TLS certificate for both PF ports. Give Terraform and the
   broker the issuing CA; do not disable certificate verification. Ensure the
   PF version and provider version match the pinned versions in
   [`versions.tf`](versions.tf).
2. Use an Entra identity with permission to create an app registration,
   service principal, application password, API-access declarations and Web
   redirect URIs in this tenant. Sign in using your chosen AzureAD provider
   credential method (for example Azure CLI). A Graph consent administrator
   must approve the requested delegated permissions where required. This
   configuration intentionally does **not** grant admin consent automatically:
   the grant API can require a directory-write-capable Terraform identity.
3. Use **encrypted, access-controlled remote Terraform state** before a real
   apply. PF client secrets, the Entra app password, and optional adapter
   credentials may appear in state even when marked sensitive. Never commit
   state, `.env`, `terraform.tfvars`, plans, or shell transcripts containing
   secrets. Supply `TF_VAR_pf_portal_client_secret`,
   `TF_VAR_pf_agent_client_secret`, and `TF_VAR_pf_broker_client_secret` via
   your secret delivery mechanism. Set
   `PINGFEDERATE_PROVIDER_USERNAME`/`PINGFEDERATE_PROVIDER_PASSWORD` for the
   provider. Do not paste values into this guide or a tracked file.
4. Create `.env` from `.env.example`. Set the licensed image credentials,
   encryption key, and local ports. The broker profile stays off on the first
   runtime apply. Keep the real runtime URL, tenant ID and client IDs aligned
   with Terraform outputs later.

## Apply order

Run from the repository root. The three Terraform directories are separate
states because PF must exist before its configuration provider can connect,
and the global OAuth singleton must be updated before clients use its scopes.

```powershell
terraform -chdir=terraform/runtime init
terraform -chdir=terraform/runtime plan
terraform -chdir=terraform/runtime apply
# Wait for the PF admin API at https://localhost:9999 to become healthy.
terraform -chdir=terraform/scopes init
terraform -chdir=terraform/scopes test
terraform -chdir=terraform/scopes plan
# Confirm the plan retains every existing PF scope and setting.
terraform -chdir=terraform/scopes apply
terraform -chdir=terraform init
terraform -chdir=terraform validate
terraform -chdir=terraform test
terraform -chdir=terraform plan
terraform -chdir=terraform apply
```

Review all plans before approval. Runtime Compose applies can recreate local
containers; keep the persistent volumes intact.
If the identity apply previously failed with `Undefined scope 'broker.connect'`,
apply the scopes state first, then rerun identity without deleting its partial
state. The scopes state imports PF's existing singleton and adds only the two
broker scopes to its existing common-scope set.
The first identity apply creates the Entra app and **disabled** PF clients
without token-manager references, then restricted token managers and mappings.
PF rejects an ATM allowlist entry until that OAuth client exists. After the
first apply succeeds, set `attach_pf_token_contract = true` in
`terraform.tfvars` and apply the identity state again. This attaches the
existing manager IDs and OIDC policy to the still-disabled clients. Do not
set `activate_clients = true` until the remaining PF contract is ready.
If the earlier apply stopped with `oauth_access_token_management_invalid_client_id`,
leave Terraform state and the existing PF objects intact and rerun the first
apply with this corrected configuration; Terraform will resume the partial
deployment.
With
`pf_handoff = null` (the default), it does **not** create the Agentless adapter
or Entra IdP connection. The AzureAD redirect resource waits for PF to return
the connection's generated OIDC redirect URI; do not invent that path.

## Development-only portal login

The separate `directory-saml-exchange` OAuth client is managed in
`saml_exchange_client.tf`. Supply its distinct `pf_saml_client_secret` in the
ignored private `terraform.tfvars` or through `TF_VAR_pf_saml_client_secret`.
Terraform exposes it through the **sensitive** `saml_exchange_client_secret`
output; protect the local state and saved plans. The client has only the
`TOKEN_EXCHANGE` grant and is disabled by default. After verifying the
prerequisites below, set `enable_saml_exchange_client = true` in the ignored
`terraform.tfvars`, review the plan, and apply. Do not enable it or set
`SAML_ENABLED=true` until a
dedicated local subject-token processor/policy, per-user SAML 1.1 mapping, and
read-only Entra OBO consent have been verified. The remote `TEST` policy is
not a substitute for the local portal's reference-token processor.

To stage the local *input* side independently, set
`create_saml_processor_policy = true` and
`pf_saml_expected_subject = "<exact portal sub>"` in private `terraform.tfvars`.
This creates an OAuth bearer token processor against `brokerUserATM` and a
one-user processor policy that checks the token's subject, portal client ID,
issuer, audience, scope, and principal type. It does not attach the policy to
the client or issue SAML. The installed provider has no SP token-generator
resource. The local generator and imported signing key are staged separately
as described below. Do not treat this input policy alone as a working exchange.
`create_saml_signing_key = true` separately generates an unused RSA signing
key inside the localhost PF instance and exposes only its public SHA-256
fingerprint. It does not configure a SAML token generator or alter Entra
federation. Do not replace a federated domain's signing certificate with this
key without first reviewing the existing domain federation and planning a
non-disruptive rollover with its owners.
For the existing `MSFT11` branch, an approved encrypted in-memory export from
`pfconsole.ping.internal.darkedges.com` was imported into localhost PF as
`broker-msft11-import`. The read-only Terraform data source in
`saml_existing_signing_key.tf` pins its SHA-256 certificate fingerprint; no
private signing key or export password is written to Terraform state. The
certificate import alone does **not** configure the SAML generator or attach
the exchange policy.
Set `stage_msft11_generator = true` with `pf_msft11_source_admin_url` to
stage a localhost generator using the reviewed source generator settings and
the fingerprint-pinned imported signing key. Terraform's PF provider 1.9.0
does not yet expose an SP token-generator resource, so this local-only bridge
uses the Admin API and verifies the signer; it cannot detect all out-of-band
drift. The source generator's Entra claim-formatting expression requires OGNL;
the same opt-in enables expressions on the **whole localhost PF instance** and
restarts that container if the setting changes. This affects which trusted PF
administrators can use expressions, so do not reuse this flag on a shared PF
server. The script also restarts any running broker/portal containers after a
PF restart because they share PF's network namespace. For a manual PF restart,
use `make restart-pf-stack` so those dependents rejoin the new namespace. It
does not attach a mapping or enable the complete exchange by itself.
Set `stage_msft11_mapping = true`, `pf_saml_entra_upn`, and
`pf_saml_immutable_id` only for the approved one-user localhost test. The
mapping repeats the exact authenticated subject check from the processor
policy and emits the Entra-compatible SAML 1.1 attributes. Once the mapping is
staged, set `stage_msft11_generator_group = true` to make a dedicated SAML 1.1
group the localhost default for requests with `requested_token_type=saml1`.
This is required when the request has no `resource` or `audience` selector;
the Admin API bridge refuses to overwrite another default group. Terraform
then attaches the dedicated policy to the exchange client. An
Entra Graph OBO exchange still needs a live browser test; applying Terraform
alone cannot prove it.

The portal's authorization-code request needs a PF OAuth user-authentication
source. For the localhost demo, set `enable_dev_login = true` in the ignored
`terraform/terraform.tfvars`, then supply a unique test password of at least
8 characters through `TF_VAR_pf_dev_login_password` in your shell or secret
manager. Do not put it in `.env`, a tracked file, or a command-line `-var`:
Terraform does not load `.env`, and the password will still be in Terraform
state. Review `terraform -chdir=terraform plan` for three new PF objects, then
apply. The account name is `broker-dev-user`.

To add `nirving@ping.darkedges.com` as a **second** localhost-only login while
keeping `broker-dev-user`, also set `enable_dev_second_login = true` and supply
a separate password privately via `TF_VAR_pf_dev_second_login_password`.
Review the plan before applying: it changes the existing credential validator
user table, and both passwords remain in Terraform state. The extra login's
OAuth `USER_KEY`/`sub` is its authenticated username. It does **not** enable a
second Reference ID or SAML token-exchange mapping: the dev handoff below
still emits `broker-dev-user` for its one exact Entra tenant/object-ID allowlist.
Do not attempt to connect the second login through that handoff until a
separate, reviewed per-user mapping is implemented.

This adds a bundled Simple Username Password Credential Validator, an HTML Form
IdP adapter, and an OAuth IdP Adapter Grant Mapping. Both `USER_KEY` and
`USER_NAME` come from the adapter's authenticated `username`, not from an email
or browser parameter. It requires localhost PF runtime and admin URLs and is disabled by
default. Remove `enable_dev_login` (or set it to false) and apply to tear down
these three test-only objects when finished; review the destroy plan first.

This does not replace PF's server-wide authentication-policy list. With one
applicable OAuth authentication source and no policy overriding it, PF should
use the mapped adapter. If the browser still returns “There are no
authentication methods available for OAuth,” inspect existing IdP policies,
default authentication sources, and OAuth source selection in that PF instance
before changing global policy settings. Do not enable this local credential
source for a shared or production PF instance.

## Local PingFederate HTTPS certificate

[Ping's DevOps certificate page](https://developer.pingidentity.com/devops/reference/usingCertificates.html)
explicitly excludes PingFederate from its `KEYSTORE_FILE`/`SECRETS_DIR`
container startup mechanism. The `compose.yaml` bind mount makes the existing
ignored `certs/` directory available read-only inside the PF container, but
**the mount alone does not select a PF certificate**. The opt-in
[`pf_local_tls.tf`](pf_local_tls.tf) imports an encrypted PKCS#12 bundle made
from the *same* `portal-key.pem` and `portal.pem` pair via PF's administrative
API and selects it for both the admin and runtime HTTPS listeners. The raw
mkcert PEM key is unencrypted and PF can reject it with “Missing encrypted
private key”; the PKCS#12 import avoids that error. Only enable this on the
localhost development PF instance. PingFederate and the provider both
[support PKCS#12 imports](https://github.com/pingidentity/terraform-provider-pingfederate/blob/main/docs/resources/keypairs_ssl_server_key.md).

Generate a current mkcert certificate for `localhost` and `127.0.0.1` as in
[`docs/PORTAL.md`](../docs/PORTAL.md), and install/trust mkcert's local CA on
the machine running the portal and Terraform. Check the certificate dates and
SANs before proceeding. Both PF ports currently serve the expired default
certificate, so the Terraform provider must already have a working,
appropriately scoped bootstrap connection to the admin API; importing the
new certificate does not itself solve bootstrap trust. Do not permanently
disable certificate verification.

In PowerShell, prepare the bundle once using a private password. The script
checks that the exported bundle contains the same certificate and private key.
The generated `.p12` remains in the Git-ignored `certs/` directory. Do not
commit it or put the password in a tracked file.

```powershell
$env:TF_VAR_pf_local_tls_keystore_password = Read-Host -MaskInput 'PF local PKCS#12 password (14+ characters)'
./scripts/prepare-pf-local-tls.ps1
```

Run this again with `-Force` only when deliberately replacing the local
bundle; replacing an imported PF key requires a separately reviewed Terraform
rotation plan because `prevent_destroy` guards it. Keep the same environment
variable set in the shell used for Terraform.

The transition has two reviewed applies:

1. Set `enable_local_pf_tls = true` in the ignored `terraform/terraform.tfvars`
   and leave `activate_local_pf_tls = false`. Plan and apply the identity
   state. Expect one new PF SSL server key, ID `broker-localhost-mkcert`.
   If a previous raw-PEM import failed, check the new plan before retrying;
   the failed key should not be present in state.
2. Set `activate_local_pf_tls = true`. Terraform's import block first adopts
   PF's existing SSL settings singleton. Review the plan closely: it will
   make the mkcert key the **only active default** on both the admin and
   runtime listener, deactivating any other active certificate. On this
   isolated localhost instance, apply after confirming that is intended.
   Recheck certificate dates, SAN and trust on both ports, then start a fresh
   portal sign-in. An already issued authorization code cannot be reused.

The PKCS#12 bundle and its password are stored in Terraform state and
potentially saved plans, even though plan output marks them sensitive. Keep
both access-controlled and encrypted. The key and settings resources have `prevent_destroy`; do not
simply turn the flags off after activation. To rotate or revert, plan a new
key/active-list transition first and preserve an administrative connection.
If the Compose runtime state manages this stack, separately review its plan
before applying the new bind mount; container recreation can interrupt the
portal login journey but must not delete the persistent PF volume.

### Development-only Entra handoff

For the isolated localhost demo, Agentless Integration Kit 2.3.1 is present in
the PF container. Its Reference ID SP adapter class and configuration labels
were checked against the installed JAR. If PF's admin API reports a different
descriptor ID, set `pf_dev_reference_adapter_plugin_id` to that ID rather than
assuming the JAR class name is the registered descriptor. The opt-in
`enable_dev_handoff` path
creates the adapter and Entra OIDC IdP connection, and registers PF's generated
callback with the Entra application. It maps the single local subject
`broker-dev-user` **only after PF issuance criteria match both** the validated
Entra tenant ID and the one allowed Entra object ID (`oid`). It does not match
email or accept identity from browser parameters. The token response is taken
from PF's `Token Endpoint Response` context (`tokenEndpointResponse`
in the admin API) and marked masked in the SP adapter
contract. Review the actual serialized pickup response on this PF version
without exposing tokens in logs or reports.

If PF reports `SpBackchannelReferenceAuthnAdapter` during response handling,
use the optional, **non-working diagnostic probe** to isolate the token
response mapping. With the dev handoff already configured, review and apply:

```powershell
terraform -chdir=terraform plan '-var=enable_dev_handoff_probe=true'
terraform -chdir=terraform apply '-var=enable_dev_handoff_probe=true'
```

This replaces only the adapter's `entra_token_response` fulfillment with the
literal `PROBE_NO_TOKEN_RESPONSE`. The `tid`/`oid` issuance checks and subject
mapping remain intact. Start a **fresh** Connect journey; do not reuse an OIDC
callback URL or authorization code. If PF now reaches the portal but the portal
reports a failed connection, the adapter accepted the simple value and the
original token-response context/serialization needs investigation. The broker
rejects the marker, so this probe cannot save a Graph connection. If PF still
raises the same adapter exception, investigate the adapter's callback,
transport, or other configuration instead. Share only the outcome, never a
callback URL, code, reference ID, or token. Restore the real mapping immediately
after the one test (with no probe override in `terraform.tfvars`):

```powershell
terraform -chdir=terraform plan
terraform -chdir=terraform apply
```

Confirm the plan changes `entra_token_response` back to PF context before
applying. No portal restart is needed for this PF mapping change.

In the ignored `terraform/terraform.tfvars`, set `enable_dev_handoff = true`
and `pf_dev_link_entra_oid` to the approved account's immutable Entra object
ID. Keep `enable_dev_login = true`; do not set the generic `pf_handoff` at the
same time. Supply `TF_VAR_pf_dev_pickup_password` privately with at least 16
characters, and set the identical value as `PF_PICKUP_PASSWORD` in the ignored
broker `.env`. `pf_dev_pickup_username` defaults to
`directory-broker-pickup`, matching `PF_PICKUP_USER` in the example. The pickup
credentials, and the Entra client secret, enter Terraform state. Review the
PF adapter, IdP connection, Entra redirect URI, and exact `tid`/`oid` issuance
criteria in the plan before applying. No live handoff is configured merely by
installing the kit.

After applying, compare the `portal_connect_start_url_candidate` output with
PF's Summary & Activation URL and its SP authentication policy. Only then
copy it into `PORTAL_PF_CONNECT_START_URL` in `.env` and restart the portal.
The dev connection now sets its own default target URL to the exact HTTPS
`/auth/reference-callback` endpoint. PingFederate allows that connection
default through SSO redirect validation, so the generated start URL does not
need a `TargetResource` parameter. If you added one while diagnosing the
adapter exception, replace the `.env` value with the current Terraform output
after applying and restart the portal. Do not disable redirect validation or
add a broad localhost wildcard; this default is scoped to the dev connection.
For `/sp/startSSO.ping`, `PartnerIdpId` must identify the partner's Entra
entity ID (URL-encoded), not PingFederate's local `entra-directory-link`
connection ID. A wrong value produces PingFederate's “No such IDP partner
connection” error page. The candidate output now uses the entity ID.
The local broker profile must also be running and healthy. Compose now shares
PF's network namespace with the broker in the local demo, so the broker can
use `https://localhost:9031` with the same mkcert SAN for introspection and
Reference ID pickup. Copy mkcert's **public** root CA for the broker's
additional trust directory (never copy `rootCA-key.pem`):

```powershell
New-Item -ItemType Directory -Force certs/ca
Copy-Item -LiteralPath (Join-Path (mkcert -CAROOT) 'rootCA.pem') -Destination certs/ca/mkcert-rootCA.pem
```

The broker mounts only `certs/ca/`, not the portal private key; its built-in
public CA bundle remains available for Entra and Graph. The runtime Terraform
state refuses to start the broker until this CA file exists. Publishing the
broker host port is done on the PF service;
review the runtime Terraform plan because Compose will recreate that container
to change its published ports. The persistent `pingfederate-out` volume must
remain intact. Before starting the broker, set a stable 32-byte base64
`TOKEN_ENCRYPTION_KEY` and all real, matching credentials in `.env`. On
PowerShell, generate the key locally with
`$bytes = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes); [Convert]::ToBase64String($bytes)`
and paste the result only into the ignored `.env`. Do not regenerate it after
the broker has stored connections, or the encrypted store will be unreadable.
The runtime Terraform state checks the key format and builds the broker image
before Compose starts it; `docker_compose` does not build a missing image.
After changing `.env` for an already-created Compose resource, review a plan
with `terraform -chdir=terraform/runtime plan '-replace=docker_compose.broker_stack' '-var=start_broker=true'`
and apply with `terraform -chdir=terraform/runtime apply '-replace=docker_compose.broker_stack' '-var=start_broker=true'`
only if the broker and PF restart is acceptable. In PowerShell, keep each flag
and its value in one quoted argument. The named volumes
persist, but the Compose project is briefly stopped and recreated.

For a non-demo setup, after installing the compatible Agentless Integration Kit,
inspect its actual Reference ID SP Adapter plugin descriptor and field names. Provide the
`pf_handoff` object with its plugin ID, adapter configuration, and four
**reviewed** attribute fulfillments. `entra_token_response` must come from
the Entra code-exchange **context**, while `subject`, `entra_tid`, and
`entra_oid` must come from validated PF/Entra identity, never request text or
an email match. Read [`docs/PINGFEDERATE.md`](../docs/PINGFEDERATE.md) before
editing these mappings. Then plan and apply the identity state again. Terraform
will register the exact generated PF callback in the Entra app. The adapter
pickup account, HTTPS portal target, and browser initiation journey must be
matched to the actual kit and portal implementation.

Set broker `.env` to the Terraform Entra client ID and secret (retrieve the
sensitive output through your secret manager), plus the exact PF endpoints and
credentials. In the local Compose profile, the broker and PF share a network
namespace and `localhost:9031` reaches PF with the mkcert SAN. In other
deployments, use a Docker-reachable hostname with a certificate SAN for that
hostname and trust its CA in the broker container. In particular set
`PF_INTROSPECTION_URL`, `PF_PICKUP_URL`, and `PF_ISSUER` to values validated
against your PF configuration; the browser-facing URL can differ from the
container-to-container hostname. Keep `BROKER_AUDIENCE` equal to the
Terraform audience. Then start the broker profile:

```powershell
terraform -chdir=terraform/runtime apply -var='start_broker=true'
```

The default broker host port is `127.0.0.1:18082`; check `/healthz` there.
Do not send real user traffic until the acceptance checks below pass.

## What still needs instance-specific Terraform work

The PF image/profile and its **global** OAuth authorization-server settings
are installation-wide. The separate `scopes` state imports the singleton,
preserves existing common scopes and required timing settings, and adds the
two broker scopes. Review its plan for unrelated changes to any global
setting before approving it; this is a server-wide resource. Likewise, a
production portal authentication source, browser routing, adapter pickup
credentials, and Agentless kit installation cannot be inferred from the three
supplied URLs.
They are necessary for an end-to-end live demo. After those pieces are in
place, set `activate_clients = true`, apply, and run the live acceptance
checks before sending ordinary traffic.

The token-manager mappings set `broker_principal_type` to fixed `user` or
`agent`, and the user `sub` comes from PF's persistent-grant `USER_KEY`. The
agent subject is its fixed client ID. This is only correct if the portal
authentication mapping sets `USER_KEY` to your immutable canonical subject.
The dev login uses `broker-dev-user` only for local testing.
The Reference ID `subject` must be the same value. Review the actual PF
introspection output for `active`, `iss`, `aud`, `exp`, `token_type`,
`client_id`, `scope`, `broker_principal_type` and user `sub`; the broker will
reject an incomplete or mismatched response. The two ATMs use the reference
bearer plugin and a 15-minute token lifetime. PF plugin field acceptance has
not been verified against your container.

## Live acceptance checks

- Confirm the Entra app has only delegated `User.ReadBasic.All` and
  `GroupMember.Read.All` Graph access; no application roles or write scopes.
- Confirm the exact PF-generated redirect URI is registered as a Web URI in
  Entra, and any required tenant consent has been granted.
- Introspect one real portal token and one real agent token. Confirm distinct
  grant types, scopes and principal types; confirm the user `sub` equals the
  immutable Reference ID `subject`.
- Perform a real Connect Microsoft journey, inspect only **redacted** pickup
  metadata, and confirm refresh, one Graph GET, delegation revocation, and
  disconnect. Never paste token responses or reference IDs into logs/issues.
- Run `go test -race -count=1 ./...`, `go vet ./...`, and
  `go build -buildvcs=false ./cmd/broker` in a supported Go environment.

Relevant provider references: [PingFederate token managers](https://registry.terraform.io/providers/pingidentity/pingfederate/latest/docs/resources/oauth_access_token_manager), [PF token mappings](https://registry.terraform.io/providers/pingidentity/pingfederate/latest/docs/resources/oauth_access_token_mapping), [PF OIDC policy](https://registry.terraform.io/providers/pingidentity/pingfederate/latest/docs/resources/openid_connect_policy), [AzureAD redirect URIs](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/application_redirect_uris).
