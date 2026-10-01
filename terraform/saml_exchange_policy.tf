# Staged, isolated policy: it is not attached to the OAuth client until a
# SAML 1.1 generator, signing trust, and per-user Entra mapping are verified.
# The bearer processor validates the opaque portal token using the same ATM
# that minted it; the policy additionally binds the authenticated subject,
# client, issuer, audience, scope, and principal type.
resource "pingfederate_idp_token_processor" "broker_user_bearer" {
  count        = var.create_saml_processor_policy ? 1 : 0
  processor_id = "brokerUserBearerProcessor"
  name         = "Directory broker user reference token processor"
  plugin_descriptor_ref = {
    id = "org.sourceid.wstrust.processor.oauth.BearerAccessTokenTokenProcessor"
  }
  configuration = {
    fields = [
      { name = "Access Token Manager", value = pingfederate_oauth_access_token_manager.user.manager_id },
      { name = "Scope value as single string", value = "true" },
    ]
  }
  attribute_contract = {
    core_attributes = [
      { name = "aud" },
      { name = "authorization_details" },
      { name = "client_id" },
      { name = "expires_at" },
      { name = "iss" },
      { name = "scope" },
    ]
    extended_attributes = [
      { name = "sub" },
      { name = "broker_principal_type" },
    ]
  }
}

resource "pingfederate_oauth_token_exchange_processor_policy" "broker_user" {
  count                = var.create_saml_processor_policy ? 1 : 0
  policy_id            = "brokerUserSamlPolicy"
  name                 = "Directory broker one-user SAML exchange input"
  actor_token_required = false
  processor_mappings = [{
    subject_token_type      = "urn:ietf:params:oauth:token-type:access_token"
    subject_token_processor = { id = pingfederate_idp_token_processor.broker_user_bearer[0].processor_id }
    attribute_contract_fulfillment = {
      subject = { source = { type = "SUBJECT_TOKEN" }, value = "sub" }
    }
    issuance_criteria = {
      conditional_criteria = [
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "sub", condition = "EQUALS", value = var.pf_saml_expected_subject },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "client_id", condition = "EQUALS", value = "directory-portal" },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "iss", condition = "EQUALS", value = var.pf_public_url },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "aud", condition = "EQUALS", value = var.broker_audience },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "scope", condition = "EQUALS", value = "broker.connect" },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "broker_principal_type", condition = "EQUALS", value = "user" },
      ]
    }
  }]
}
