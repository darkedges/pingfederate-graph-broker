# The client is provisioned independently, then attached to the dedicated
# one-user exchange policy only after its Entra-trusted SAML 1.1 mapping exists.
resource "pingfederate_oauth_client" "saml_exchange" {
  client_id = "directory-saml-exchange"
  name      = "Directory broker SAML exchange"
  enabled   = var.enable_saml_exchange_client

  client_auth = {
    type   = "SECRET"
    secret = var.pf_saml_client_secret
  }

  grant_types = ["TOKEN_EXCHANGE"]

  token_exchange_processor_policy_ref = var.stage_msft11_mapping ? {
    id = pingfederate_oauth_token_exchange_processor_policy.broker_user[0].policy_id
  } : null

  depends_on = [terraform_data.msft11_generator_group_stage]

  lifecycle {
    precondition {
      condition = (
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_admin_url)) &&
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_public_url))
      )
      error_message = "The SAML exchange client is scoped to the localhost PingFederate instance."
    }
    precondition {
      condition     = !var.enable_saml_exchange_client || var.stage_msft11_generator_group
      error_message = "Do not enable the SAML exchange client before the SAML 1.1 generator group is staged."
    }
  }
}
