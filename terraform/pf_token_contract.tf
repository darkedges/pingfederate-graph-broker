# Dedicated reference-bearer token managers. The mappings below are the broker
# contract; a live introspection response must still be checked field by field.
locals {
  reference_bearer_plugin = "org.sourceid.oauth20.token.plugin.impl.ReferenceBearerAccessTokenManagementPlugin"
  broker_token_attributes = [
    { name = "iss" },
    { name = "aud" },
    { name = "sub" },
    { name = "broker_principal_type" },
  ]
  reference_bearer_fields = [
    { name = "Token Length", value = "56" },
    { name = "Token Lifetime", value = "15" },
  ]
}

resource "pingfederate_oauth_access_token_manager" "user" {
  # PF validates allowlisted client IDs at creation time. These three clients
  # are initially disabled and have no ATM refs, so there is no dependency loop.
  depends_on = [pingfederate_oauth_client.portal, pingfederate_oauth_client.broker]
  manager_id = "brokerUserATM"
  name       = "Directory broker user reference tokens"
  plugin_descriptor_ref = {
    id = local.reference_bearer_plugin
  }
  configuration      = { fields = local.reference_bearer_fields }
  attribute_contract = { extended_attributes = local.broker_token_attributes }
  access_control_settings = {
    restrict_clients = true
    allowed_clients  = [{ id = "directory-portal" }, { id = "directory-broker-rs" }]
  }
}

resource "pingfederate_oauth_access_token_manager" "agent" {
  depends_on = [pingfederate_oauth_client.agent, pingfederate_oauth_client.broker]
  manager_id = "brokerAgentATM"
  name       = "Directory broker agent reference tokens"
  plugin_descriptor_ref = {
    id = local.reference_bearer_plugin
  }
  configuration      = { fields = local.reference_bearer_fields }
  attribute_contract = { extended_attributes = local.broker_token_attributes }
  access_control_settings = {
    restrict_clients = true
    allowed_clients  = [{ id = "directory-agent" }, { id = "directory-broker-rs" }]
  }
}

resource "pingfederate_oauth_access_token_mapping" "user" {
  context                  = { type = "DEFAULT" }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.user.id }
  attribute_contract_fulfillment = {
    iss                   = { source = { type = "TEXT" }, value = var.pf_public_url }
    aud                   = { source = { type = "TEXT" }, value = var.broker_audience }
    sub                   = { source = { type = "OAUTH_PERSISTENT_GRANT" }, value = "USER_KEY" }
    broker_principal_type = { source = { type = "TEXT" }, value = "user" }
  }
}

resource "pingfederate_oauth_access_token_mapping" "agent" {
  context                  = { type = "CLIENT_CREDENTIALS" }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.agent.id }
  attribute_contract_fulfillment = {
    iss                   = { source = { type = "TEXT" }, value = var.pf_public_url }
    aud                   = { source = { type = "TEXT" }, value = var.broker_audience }
    sub                   = { source = { type = "TEXT" }, value = "directory-agent" }
    broker_principal_type = { source = { type = "TEXT" }, value = "agent" }
  }
}

resource "pingfederate_openid_connect_policy" "portal" {
  policy_id                = "brokerPortalOIDC"
  name                     = "Directory broker portal OIDC"
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.user.id }
  attribute_contract       = { extended_attributes = [] }
  attribute_mapping = {
    attribute_contract_fulfillment = {
      sub = { source = { type = "TOKEN" }, value = "sub" }
    }
  }
  allow_id_token_introspection = false
}
