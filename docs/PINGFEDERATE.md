# PingFederate 13.1 and Entra configuration

## What is configured and what is coded

The Go service handles pickup, storage, refresh, delegation and Graph requests. You
configure PF/Entra and integrate the browser redirect with your portal. This repository
does not invent a PF configuration export: connection IDs, certificates, policy paths,
canonical subjects and adapter contracts depend on your installation.

## 1. Dedicated Entra app registration

Create a single-tenant confidential web app for this connector. Register the exact
redirect URI reported by the PF OIDC IdP connection. Add Microsoft Graph delegated
`User.ReadBasic.All` and `GroupMember.Read.All`, plus the OIDC/offline permissions needed
by your tenant. Obtain administrator consent where required. Do not add application
permissions or write scopes to this registration for this use case.

For this starter, configure PF's upstream client authentication as POST with a client
secret. The broker uses the same Entra client ID and a valid secret for that registration.
Those credentials belong to the same logical OAuth client, even though acquisition and
refresh run in separate components. Use a dedicated secret delivery mechanism for both.
Certificate/private-key client authentication is a future enhancement to this starter.

Use tenant-specific discovery:

```text
https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration
```

## 2. Upstream Entra OIDC IdP connection

In PF, create/configure an OIDC IdP connection under Authentication → Integration →
IdP Connections. Enable browser SSO and use Code login type with PKCE. Configure the
tenant metadata, client ID, secret, and this space-separated scope string:

```text
openid profile offline_access https://graph.microsoft.com/User.ReadBasic.All https://graph.microsoft.com/GroupMember.Read.All
```

Route a dedicated connection journey to this IdP connection. The route must perform
a fresh upstream code exchange for a new link; a cached PF authentication session
containing no upstream token response cannot complete it. Existing Entra SSO may avoid
another credential prompt, but consent/Conditional Access can still require interaction.
If Entra federates authentication back to PF, ensure that inbound Microsoft
authentication uses the appropriate local authentication path, not the Entra connection
again, to avoid a federation loop.

## 3. Reference ID SP Adapter handoff

Use a compatible Agentless Integration Kit and create a Reference ID SP Adapter for
the trusted portal backend. Set:

| Setting | Starter value/requirement |
|---|---|
| Adapter ID | `graphDirectoryLink`, or match `PF_SP_ADAPTER_ID` |
| Target application URL | `https://localhost:8788/auth/reference-callback` for the local portal |
| Outgoing attribute format | JSON |
| Transport mode | Form POST (Agentless 2.3.1 configuration value `2`) |
| Reference duration | Start with 60 seconds and measure the callback latency |
| Require SSL/TLS | Enabled |
| Pickup authentication | Dedicated HTTP Basic credentials over TLS, matching the broker env |

The localhost Terraform handoff sets the IdP connection's default target URL
to that exact HTTPS callback. This supplies the destination for
`/sp/startSSO.ping` without a `TargetResource` parameter and keeps
PingFederate's SSO redirect validation enabled. Do not replace it with a
server-wide wildcard or turn validation off.

The starter's pickup client uses Basic authentication. Agentless also supports other
methods, but bearer/mTLS pickup is not implemented in this version. Scope the adapter
and network access to the broker and remove unrelated pickup authentication options.

Map the Entra IdP connection to this SP adapter, directly or through a private policy
contract, using these **application-defined attribute names**:

| Attribute | Meaning/source |
|---|---|
| `subject` | Canonical PF user ID, exactly matching the portal access token's `sub` |
| `entra_tid` | Validated Entra provider claim `tid` (`CLAIMS` source) |
| `entra_oid` | Validated Entra provider claim `oid` (`CLAIMS` source) |
| `entra_token_response` | Context → Token Endpoint Response (`tokenEndpointResponse` API mapping value) from this Entra code exchange |

PF 13.1 documents the token-response context. The broker accepts `entra_token_response`
as an object, JSON string or singleton array of JSON strings. Other attributes may be
strings or singleton string arrays. For PF pickup only, `expires_in` may be a
JSON number (including a fractional or exponent representation) or a canonical
decimal integer string such as `"3600"`. Fractional seconds are rounded down;
the same 1–86400 second validation still applies. Entra refresh responses retain
their strict integer requirement. The following illustrates the required pickup
payload; values are fake:

```json
{
  "subject": "canonical-user-id",
  "entra_tid": "11111111-1111-1111-1111-111111111111",
  "entra_oid": "22222222-2222-2222-2222-222222222222",
  "entra_token_response": {
    "access_token": "FAKE_ACCESS_TOKEN",
    "refresh_token": "FAKE_REFRESH_TOKEN",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid profile User.ReadBasic.All GroupMember.Read.All"
  }
}
```

Validate the raw-context serialization in your PF installation. This guide intentionally
does not supply an unverified OGNL expression. If your mapping produces a Java object
rather than the JSON value shown above, configure a reviewed transformation or adapter
at that boundary and test the resulting payload. Do not broaden the broker to accept
unsigned browser-supplied tokens as a shortcut. Mark token-bearing attributes masked
in PF logging and restrict the contract to the adapter. Never map this response into
normal access-token/ID-token claims or other SP assertions.

If the broker reports `invalid_token_response_format`, its DEBUG
`reference_pickup` event includes a fixed `format_shape` category (for example,
`string_non_json` or `object_field_type_expires_in_non_decimal_string`). The
`expires_in` categories distinguish arrays, objects, booleans, non-integer
numbers, and noncanonical or non-decimal strings without including their values.
This classification contains no value from the response. It identifies the serialization boundary to fix;
never copy the pickup response, reference ID, or token into logs or support notes.

For localhost diagnosis only, Terraform's `enable_dev_handoff_probe` can replace
this one fulfillment with a harmless literal to test whether the Reference ID
adapter handles a simple value. The broker rejects it and cannot create a
connection. Keep the exact `tid`/`oid` issuance checks and restore the context
mapping immediately afterward; see `terraform/README.md` for the test steps.

**Identity binding:** `subject` must be derived by PF from validated identity and any
approved account-link mapping. For a new Entra-only portal you can consistently use
`{tid}:{oid}` as the canonical subject in both flows. For an existing portal, use its
established immutable identity mapping. The broker rejects a different subject; it
does not auto-link by email, UPN or a browser-provided user ID.

## 4. PF clients and token claims

For a localhost-only portal sign-in, the optional Terraform dev login creates
a Simple Username Password Credential Validator, HTML Form IdP adapter, and
OAuth IdP Adapter Grant Mapping. The mapped, authenticated username supplies
both persistent-grant `USER_KEY` and `USER_NAME`; for its single test account
the canonical subject is `broker-dev-user`. See the
[Terraform dev-login instructions](../terraform/README.md#development-only-portal-login).
It is not a production identity source. The Reference ID handoff must derive
its `subject` from a reviewed trusted identity mapping to the *same* canonical
value; an Entra email or browser-supplied value is not interchangeable with
the local test username. Terraform does not alter the server-wide IdP policy
list for this option.

For the one-account localhost demo, `enable_dev_handoff` implements that
mapping as an exact tenant-ID and Entra object-ID allowlist in PF issuance
criteria. Only after both validated OIDC claims match does the mapping emit
the fixed `broker-dev-user` subject. This is an explicit one-to-one dev account
link, not a general account-matching rule. Review the criteria in the Terraform
plan and verify a mismatched Entra account cannot complete pickup.

Create three distinct PF client roles:

1. **Portal client**: confidential authorisation-code flow, PKCE, scope `broker.connect`.
   User authentication is mandatory. Do not permit a client-credentials grant to mint
   tokens with this user authority. Its ID is in `PF_PORTAL_CLIENT_IDS`.
2. **Agent client**: client-credentials flow, scope `broker.directory.read`. Its ID is
   in `PF_AGENT_CLIENT_IDS`. This token identifies the agent workload. The broker's
   delegation determines which user connection it may use.
3. **Broker resource-server client**: confidential client authorised to introspect
   tokens issued by the broker's ATM. Its credentials are
   `PF_INTROSPECTION_CLIENT_ID` / `PF_INTROSPECTION_CLIENT_SECRET`.

Use a dedicated ATM/audience for the broker. Both portal and agent access tokens must
introspect with the following attributes. A successful example for the portal is:

```json
{
  "active": true,
  "token_type": "Bearer",
  "iss": "https://pf.example.com",
  "aud": "https://directory-broker.example.com",
  "exp": 2000000000,
  "client_id": "directory-portal",
  "sub": "canonical-user-id",
  "scope": "broker.connect",
  "broker_principal_type": "user"
}
```

For an agent, use its client ID, scope `broker.directory.read` and a **fixed mapped**
`broker_principal_type` of `agent`. The claim is a contract introduced by this broker,
not a built-in PF claim. Set it from trusted per-client/per-flow mappings. The audience
can also be an array containing the broker audience. The issuer is an exact comparison,
including trailing slash. Refresh tokens and ID tokens must not satisfy this access-token
contract. If your ATM does not expose these values by default, explicitly map them.

## 5. Portal browser-flow contract

The broker intentionally has no unauthenticated browser callback. The local portal
in [`docs/PORTAL.md`](PORTAL.md) performs this sequence:

1. Authenticate its user through PF and keep the user's PF access token on its backend.
2. After the user chooses **Connect Microsoft**, call `POST /v1/link-intents` with that
   user token. Save the returned intent ID in the server-side browser session.
   Protect the initiating action against CSRF.
3. Send the browser into the configured PF SP connection journey. Bind the return to
   the server-side session and unexpired, one-use intent; only fixed/allowlisted portal return URLs are allowed.
   The exact SSO initiation URL is supplied by your PF connection configuration.
4. The Reference ID SP Adapter posts `REF` and `TargetResource` to the portal callback
   in Form POST mode. Verify the expected session, PF origin and pending intent,
   and require `TargetResource` to equal the portal's exact reference callback URL;
   never use the submitted value as a redirect. Then call
   `POST /v1/link-intents/{id}/complete` using the **same user's** PF token and a JSON
   body `{"reference":"<REF>"}`. PF tokens must stay off URLs and browser storage.
5. The broker retrieves attributes directly from PF, checks ownership and tenant,
   redeems the refresh token with the configured Entra client, and returns connection
   metadata. Clear the pending intent. A failed completion consumes the intent;
   restart the connection flow rather than replaying the reference.
6. Let the user explicitly select the configured agent, read operations and expiry.
   Call the delegation endpoint and give only its returned delegation ID to the agent.

Portal sign-out clears its local session and redirects the browser to PingFederate's
OIDC RP-initiated logout endpoint, then back to the registered portal root. PingFederate
may ask the user to confirm logout when no ID token hint is supplied. Browser logout
does not revoke a saved delegation; that is what permits
background work. Supply a visible Disconnect/Revoke action in the portal. A disconnect
deletes the broker's copy and delegations; it is not a tenant-wide Entra consent revocation.

## Primary references

- [PF 13.1 target session fulfillment](https://docs.pingidentity.com/pingfederate/13.1/administrators_reference_guide/pf_configuring_target_session_fulfillment.html)
- [OIDC IdP connection configuration](https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_creating_oidc_idp_connection.html) — general connection workflow; use your 13.1 console for current fields.
- [Reference ID SP flow](https://docs.pingidentity.com/integrations/agentless/pf_agentless_ik_overview_of_the_service_provider_sso_flow.html)
- [Reference ID SP settings](https://docs.pingidentity.com/integrations/agentless/custom_application_setup/pf_agentless_ik_reference_id_sp_adapter_settings_reference.html)
- [Attribute pickup process](https://docs.pingidentity.com/integrations/agentless/custom_application_setup/pf_agentless_ik_attribute_pickup_process.html)
- [Attribute drop-off process](https://docs.pingidentity.com/integrations/agentless/custom_application_setup/pf_agentless_ik_attribute_drop_off_process.html) — for IdP-style applications; this SP handoff uses pickup, not drop-off.
- [Agentless authentication methods](https://docs.pingidentity.com/integrations/agentless/custom_application_setup/pf_agentless_ik_authentication_methods.html)
- [Attribute formatting](https://docs.pingidentity.com/integrations/agentless/custom_application_setup/pf_agentless_ik_attribute_formatting.html)
- [PF introspection endpoint](https://docs.pingidentity.com/pingfederate/13.1/developers_reference_guide/pf_introspec_endpoint.html)
- [Entra authorisation code and refresh flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Refresh token client binding and lifecycle](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens)

Documentation reviewed 23 September 2026. A successful Terraform apply does not by
itself verify the live PF/Entra browser journey or Reference ID pickup payload.
