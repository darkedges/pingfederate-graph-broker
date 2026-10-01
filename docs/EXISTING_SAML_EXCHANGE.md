# Existing PingFederate JWT-to-SAML exchange (read-only inventory)

Inspected 27 September 2026 through the certificate-valid PingFederate admin
API at `pfconsole.ping.internal.darkedges.com` and the read-only deployment
metadata of `broker/darkedges-entraid-tokenexchange`. This is a configuration
inventory, **not** an export of credentials, keys, SAML assertions, or tokens.
No configuration was changed and no live exchange was performed.

## What is configured

| Component | Observed setting |
|---|---|
| OAuth client | `contact-hr-saml-client`, enabled; authorization-code and token-exchange grants; client-secret authentication; token-exchange policy `TEST` |
| Processor policy | `TEST`, actor token not required; subject token type `urn:ietf:params:oauth:token-type:jwt`; processor `PFSubjectProcessor` |
| JWT processor | `PFSubjectProcessor`; issuer `https://id.ping.darkedges.com`; JWKS URL `https://id.ping.darkedges.com/pf/JWKS`; audiences `contact-hr-client` and `contact-hr-saml-client`; audience, expiration, and issued-at checks required |
| Generator group | `TEGG`, the default group; maps `urn:ietf:params:oauth:token-type:saml2` to `MSFTSAML2` (default) and `urn:ietf:params:oauth:token-type:saml1` to `MSFT11` |
| SAML 2.0 generator | `MSFTSAML2`; issuer `https://ping.darkedges.com`; audience `urn:federation:MicrosoftOnline`; bearer confirmation; RSA-SHA256 signing; signing certificate configured; 2 minutes before and 20 minutes after |
| SAML 1.1 generator | `MSFT11`; same issuer and audience; bearer confirmation; RSA-SHA256 signing; signing certificate configured; 10 minutes before and after |
| Generator mappings | `TEST|MSFTSAML2` and `TEST|MSFT11` |

### The `TEST` → `MSFT11` branch

This is the specific SAML 1.1 branch. The default generator group `TEGG`
selects `MSFT11` when the OAuth exchange request specifies
`requested_token_type=urn:ietf:params:oauth:token-type:saml1`; the group's
default mapping, when no type is specified, is SAML 2.0 instead. The mapping
`TEST|MSFT11` has no conditional issuance criteria. It fulfills `UPN`,
`ImmutableID`, `emailaddress`, and `SAML_SUBJECT` from `TEXT` (literal)
sources. Those identity literals were not exported and must be replaced by
validated per-user mappings before reuse.

`MSFT11` emits a signed SAML 1.1 bearer assertion with issuer
`https://ping.darkedges.com`, audience `urn:federation:MicrosoftOnline`,
RSA-SHA256 signature, and a configured signing certificate. Its validity
configuration is 10 minutes before and 10 minutes after. The consuming
application separately declares the Entra grant
`urn:ietf:params:oauth:grant-type:saml1_1-bearer`. These settings describe
the intended two-stage exchange; they do not establish that the resulting
Entra access token has the broker's required Graph scopes.

The default processor policy is **`PROCESSORPOLICIES`**, not `TEST`.
The named client explicitly selects `TEST`. The default generator group is
`TEGG`; its configured resource URI is `https://localhost/app`, which looks
development-specific and must not be copied into a new production flow.

The `TEST` processor policy has no actor requirement and no conditional
issuance criteria. Its `subject` and `email` outputs use `TEXT` (literal)
sources. The SAML 2.0 generator mapping also uses `TEXT` sources for its
subject and Microsoft identity claims, and has no conditional issuance
criteria. Those literal values were intentionally not exported. They are
**not** an acceptable per-user identity mapping for this broker. Any reuse
must derive the subject and claims from a validated, canonical authenticated
identity, and must bind them to the exact user connection rather than email.

## Flow boundary

The configured PingFederate leg is conceptually:

```text
PF JWT for the configured audience
  -> PF OAuth token-exchange grant via contact-hr-saml-client and TEST
  -> signed SAML 2.0 or SAML 1.1 assertion for MicrosoftOnline
  -> consuming application's Entra SAML-bearer request (configured, not exercised)
```

The associated application's deployment identifies the consumer and its
non-secret settings:

| Setting | Observed value |
|---|---|
| Application ingress | `broker.ping.darkedges.com` |
| PF runtime exchange URL | `https://id.ping.darkedges.com/as/token.oauth2` |
| PF SAML exchange client | `contact-hr-saml-client` |
| Entra SAML 2.0 grant | `urn:ietf:params:oauth:grant-type:saml2-bearer` |
| Entra SAML 1.1 grant | `urn:ietf:params:oauth:grant-type:saml1_1-bearer` |
| Entra SAML client ID | `edd9f241-d550-4de8-845d-3fa299090014` |
| Entra SAML requested scopes | `api://e83c2af3-43d1-4f62-8bff-e619c29b5026/access_as_user openid profile email` |
| Entra sign-in tenant | `4161be3f-bf2b-41d4-a02b-e6f82b529d53` |
| Separate CIAM setting | tenant `287d8069-6760-4536-be30-e0557a5bf7a4`, scope `https://graph.microsoft.com/.default` |

The deployment references its client secrets through Kubernetes Secrets;
their values were not read. The configuration shows an intended Entra
SAML-bearer exchange, but it does **not** prove a successful token request or
Graph consent. The SAML path requests a **custom API** scope, not Graph's
`User.ReadBasic.All` and `GroupMember.Read.All`. The separate CIAM Graph
`.default` setting does not by itself show that Graph is reached through the
same SAML exchange path. The `MSFTOAuth` OIDC connection likewise requests
the custom API's `access_as_user` scope.

Microsoft documents a SAML-bearer route for a specific AD FS-issued SAMLv1
scenario; do not infer from the PF generator's Microsoft audience alone that
Entra supports the same exchange for this PF-issued assertion. Verify the
existing consuming application's token request and Entra app registration
without copying assertions or tokens into logs or browser storage.

## Broker reuse decision

Do not import the literal `TEST` identity mapping or use its SAML output as a
Graph bearer token. Before implementing a new broker path, establish:

1. Confirm the consuming application's SAML-bearer request actually succeeds
   for a PF-issued assertion and returns a token for the intended API. The
   configured grant names alone are not an interoperability test.
2. The Entra tenant/app registration and delegated Graph consent. This
   inventory's Microsoft tenant differs from the local broker tenant
   previously configured in this project.
3. A per-user, immutable subject mapping and replay/audience/expiry checks;
   no static subject or email-based linking.
4. Whether the resulting Entra grant includes a refresh token with the exact
   narrow Graph scopes the current broker requires. If not, this is a new
   broker flow and needs its own secure lifecycle design, rather than being
   fed into the existing refresh-token import path.

Until those points are verified, the existing dedicated Entra authorization-
code connection described in [PINGFEDERATE.md](PINGFEDERATE.md) remains the
supported broker path.

References: [PingFederate token exchange configuration](https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_config_oauth_token_exchange.html),
[PingFederate generator groups](https://docs.pingidentity.com/pingfederate/12.0/administrators_reference_guide/pf_creating_token_exchange_generator_groups.html),
[Microsoft SAML bearer scenario and its restrictions](https://learn.microsoft.com/en-us/entra/identity-platform/v2-saml-bearer-assertion).
