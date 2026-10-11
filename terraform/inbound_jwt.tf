variable "inbound_first_jwt" {
  type    = bool
  default = false
}
variable "inbound_first_issuer" {
  type    = string
  default = null
}
locals { inbound_first_issuer = coalesce(var.inbound_first_issuer, var.pf_public_url) }

resource "pingfederate_openid_connect_policy" "inbound_jwt" {
  count                                   = var.create_inbound_entra_first_policy ? 1 : 0
  policy_id                               = "brokerEntraOIDC"
  name                                    = "Development Entra-first ID tokens"
  access_token_manager_ref                = { id = pingfederate_oauth_access_token_manager.inbound_jwt[0].manager_id }
  attribute_contract                      = { extended_attributes = [] }
  attribute_mapping                       = { attribute_contract_fulfillment = { sub = { source = { type = "TOKEN" }, value = "sub" } } }
  id_token_lifetime                       = 5
  return_id_token_on_token_exchange_grant = true
  allow_id_token_introspection            = false
}

resource "pingfederate_keypairs_signing_key" "inbound_jwt" {
  count         = var.create_inbound_entra_first_policy ? 1 : 0
  key_id        = "broker-entra-jwt"
  key_algorithm = "RSA"
  key_size      = 2048
  valid_days    = 365
  common_name   = "broker-entra-jwt"
  organization  = "Directory broker development inspector"
  country       = "AU"
}

resource "pingfederate_oauth_access_token_manager" "inbound_jwt" {
  count                 = var.create_inbound_entra_first_policy ? 1 : 0
  manager_id            = "brokerEntraJWT"
  name                  = "Development Entra-first signed JWT"
  plugin_descriptor_ref = { id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin" }
  configuration = {
    fields = [
      { name = "Token Lifetime", value = "5" },
      { name = "JWS Algorithm", value = "RS256" },
      { name = "Active Signing Certificate Key ID", value = "broker-entra-jwt" },
      { name = "JWT ID Claim Length", value = "22" },
      { name = "Issuer Claim Value", value = local.inbound_first_issuer },
      { name = "Audience Claim Value", value = var.broker_audience },
      { name = "Publish Keys to the PingFederate JWKS Endpoint", value = "true" },
    ]
    tables = [{ name = "Certificates", rows = [{ fields = [
      { name = "Key ID", value = "broker-entra-jwt" },
      { name = "Certificate", value = pingfederate_keypairs_signing_key.inbound_jwt[0].key_id },
    ] }] }]
  }
  attribute_contract = { extended_attributes = local.broker_token_attributes }
  access_control_settings = {
    restrict_clients = true
    allowed_clients  = [{ id = pingfederate_oauth_client.inbound_first[0].client_id }, { id = pingfederate_oauth_client.broker.client_id }]
  }
}

resource "pingfederate_oauth_access_token_mapping" "inbound_jwt" {
  count                    = var.create_inbound_entra_first_policy ? 1 : 0
  context                  = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY", context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.inbound_first[0].policy_id } }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.inbound_jwt[0].manager_id }
  attribute_contract_fulfillment = {
    sub                   = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "subject" }
    iss                   = { source = { type = "TEXT" }, value = local.inbound_first_issuer }
    aud                   = { source = { type = "TEXT" }, value = var.broker_audience }
    broker_principal_type = { source = { type = "TEXT" }, value = "user" }
  }
}
