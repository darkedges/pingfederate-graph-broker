# Dedicated read-only Entra app for SAML OBO

This is a separate Terraform state for tenant `4161be3f-bf2b-41d4-a02b-e6f82b529d53`. It creates a new middle-tier app exposing `access_as_user`, pre-authorizes the existing PingFederate SAML client, and grants the new app only delegated Microsoft Graph `User.ReadBasic.All` and `GroupMember.Read.All`. It does not modify or remove the permissions of the existing working OBO app.

Sign in locally to the target tenant with an identity allowed to create app registrations, secrets, and tenant-wide delegated permission grants. For Azure CLI authentication, use `az login --tenant 4161be3f-bf2b-41d4-a02b-e6f82b529d53` and check the selected tenant before applying. Do not send credentials or tokens in chat. Configure encrypted, access-controlled Terraform state first: the app secret is stored in state despite the sensitive output marker. Review the plan and have an Entra administrator approve the delegated grant.

```powershell
terraform -chdir=terraform/saml-obo init
terraform -chdir=terraform/saml-obo validate
terraform -chdir=terraform/saml-obo plan
terraform -chdir=terraform/saml-obo apply
```

After a successful apply, set the broker's local `.env` to the new output values:

```text
SAML_ENTRA_SCOPE=<scope output> openid profile email
SAML_OBO_CLIENT_ID=<client_id output>
SAML_OBO_CLIENT_SECRET=<client_secret output, retrieved securely>
```

Keep `SAML_ENTRA_CLIENT_ID` and its secret pointing to the existing PingFederate SAML client. Restart the broker after updating its secrets. Verify the Graph token has only the two read scopes; the broker must continue rejecting broader tokens. If the SAML client cannot request the new API scope, grant that existing client delegated access to the new API in Entra and consent to it; do not broaden the Graph grant on either app.
