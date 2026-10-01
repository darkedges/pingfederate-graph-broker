# One explicitly approved subject only. The processor policy first validates
# the reference token's authenticated subject/client/issuer/audience/scope/type.
# This mapping repeats the exact subject check before emitting the four Entra
# SAML attributes. No email-based account discovery is performed.
resource "pingfederate_oauth_token_exchange_token_generator_mapping" "broker_user_msft11" {
  count     = var.stage_msft11_mapping ? 1 : 0
  source_id = pingfederate_oauth_token_exchange_processor_policy.broker_user[0].policy_id
  target_id = "brokerMsft11"

  attribute_contract_fulfillment = {
    SAML_SUBJECT = { source = { type = "TEXT" }, value = var.pf_saml_immutable_id }
    ImmutableID  = { source = { type = "TEXT" }, value = var.pf_saml_immutable_id }
    UPN          = { source = { type = "TEXT" }, value = var.pf_saml_entra_upn }
    emailaddress = { source = { type = "TEXT" }, value = var.pf_saml_entra_upn }
  }

  issuance_criteria = {
    conditional_criteria = [
      {
        source         = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
        attribute_name = "subject"
        condition      = "EQUALS"
        value          = var.pf_saml_expected_subject
      },
    ]
  }

  depends_on = [terraform_data.msft11_generator_stage]
}
