# Generate the private key inside PF. Terraform stores certificate metadata,
# not the private key. Do not use this key for SAML until Entra's federation
# trust and the generator's issuer/audience/subject mapping are reviewed.
resource "pingfederate_keypairs_signing_key" "broker_saml" {
  count         = var.create_saml_signing_key ? 1 : 0
  key_id        = "broker-saml-local-2026"
  key_algorithm = "RSA"
  key_size      = 2048
  valid_days    = 365
  common_name   = "broker-saml-local-2026"
  country       = "AU"
  organization  = "Directory broker local development"

  lifecycle {
    precondition {
      condition = (
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_admin_url)) &&
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_public_url))
      )
      error_message = "The staged SAML signing key is scoped to the localhost PingFederate instance."
    }
  }
}
