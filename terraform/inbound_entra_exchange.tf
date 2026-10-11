# Deliberately opt-in: provision separately, then verify the live exchange
# before enabling the broker and portal feature flags.
variable "create_inbound_entra_exchange_policy" {
  type        = bool
  default     = false
  description = "Provision the dedicated actor-bound PF exchange and Entra web client; runtime feature flags remain separate."
}

variable "inbound_entra_processor_id" {
  type        = string
  default     = "brokerInboundMicrosoft"
  description = "ID for the managed Microsoft JWT processor configured for the broker tenant and exact API audience."
}

variable "inbound_entra_object_id" {
  type        = string
  default     = "4576e3b2-c5dc-4f1c-af69-1c5042eb538d"
  description = "Immutable Entra object ID explicitly linked to pf_saml_expected_subject; never an email lookup."
  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.inbound_entra_object_id))
    error_message = "Provide an Entra object UUID, not an email or on-premises immutable ID."
  }
}

resource "pingfederate_idp_token_processor" "inbound_portal_actor" {
  count        = var.create_inbound_entra_exchange_policy ? 1 : 0
  processor_id = "brokerInboundActor"
  name         = "Broker inbound exchange portal actor"
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
    core_attributes     = [for name in ["aud", "authorization_details", "client_id", "expires_at", "iss", "scope"] : { name = name }]
    extended_attributes = [{ name = "sub" }, { name = "broker_principal_type" }]
  }
}

resource "pingfederate_oauth_token_exchange_processor_policy" "inbound_entra" {
  count                = var.create_inbound_entra_exchange_policy ? 1 : 0
  policy_id            = "brokerInboundEntraPolicy"
  name                 = "Broker Entra exchange with bound portal actor"
  actor_token_required = true
  processor_mappings = [{
    subject_token_type      = "urn:ietf:params:oauth:token-type:access_token:msft"
    subject_token_processor = { id = pingfederate_idp_token_processor.inbound_microsoft[0].processor_id }
    actor_token_type        = "urn:ietf:params:oauth:token-type:access_token"
    actor_token_processor   = { id = pingfederate_idp_token_processor.inbound_portal_actor[0].processor_id }
    attribute_contract_fulfillment = {
      subject = { source = { type = "ACTOR_TOKEN" }, value = "sub" }
    }
    issuance_criteria = {
      conditional_criteria = concat([
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "tid", condition = "EQUALS", value = local.inbound_tenant_id },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "oid", condition = "EQUALS", value = var.inbound_entra_object_id },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "scp", condition = "EQUALS", value = "access_as_user" },
        ], [for name, value in {
          sub                   = var.pf_saml_expected_subject
          client_id             = "directory-portal"
          iss                   = var.pf_public_url
          aud                   = var.broker_audience
          scope                 = "broker.connect"
          broker_principal_type = "user"
      } : { source = { type = "ACTOR_TOKEN" }, attribute_name = name, condition = "EQUALS", value = value }])
    }
  }]
  lifecycle {
    precondition {
      condition     = trimspace(var.inbound_entra_processor_id) != "" && trimspace(var.pf_saml_expected_subject) != ""
      error_message = "A verified Microsoft processor (exposing tid and oid) and canonical PF subject are required."
    }
  }
}

resource "pingfederate_idp_token_processor" "inbound_microsoft" {
  count                 = var.create_inbound_entra_exchange_policy ? 1 : 0
  processor_id          = var.inbound_entra_processor_id
  name                  = "Broker Microsoft API JWT validation"
  plugin_descriptor_ref = { id = "com.pingidentity.pf.tokenprocessors.jwt.JwtTokenProcessor" }
  configuration = {
    fields = [
      { name = "Require Audience", value = "true" },
      { name = "Require Expiration Time", value = "true" },
      { name = "Allowed Clock Skew", value = "0" },
    ]
    tables = [
      { name = "Allowed Issuers", rows = [for issuer in ["https://sts.windows.net/${local.inbound_tenant_id}/", "https://login.microsoftonline.com/${local.inbound_tenant_id}/v2.0"] : {
        fields = [{ name = "Issuer", value = issuer }, { name = "JWKS URL", value = "https://login.microsoftonline.com/${local.inbound_tenant_id}/discovery/v2.0/keys" }]
      }] },
      { name = "Allowed Audiences", rows = [for audience in ["e83c2af3-43d1-4f62-8bff-e619c29b5026", "api://e83c2af3-43d1-4f62-8bff-e619c29b5026"] : { fields = [{ name = "Audience", value = audience }] }] },
    ]
  }
  attribute_contract = {
    core_attributes     = [{ name = "sub" }]
    extended_attributes = [for name in ["tid", "oid", "scp"] : { name = name }]
  }
}

variable "inbound_pf_client_secret" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Dedicated inbound PF exchange client secret; deliver the same value to INBOUND_PF_CLIENT_SECRET."
}

resource "pingfederate_oauth_client" "inbound_exchange" {
  count                                    = var.create_inbound_entra_exchange_policy ? 1 : 0
  client_id                                = "directory-entra-exchange"
  name                                     = "Broker inbound Entra exchange"
  enabled                                  = var.activate_inbound_clients
  client_auth                              = { type = "SECRET", secret = var.inbound_pf_client_secret }
  grant_types                              = ["TOKEN_EXCHANGE"]
  restricted_scopes                        = ["broker.connect"]
  restrict_scopes                          = true
  default_access_token_manager_ref         = var.activate_inbound_clients ? { id = "brokerInboundATM" } : null
  restrict_to_default_access_token_manager = var.activate_inbound_clients
  token_exchange_processor_policy_ref      = { id = pingfederate_oauth_token_exchange_processor_policy.inbound_entra[0].policy_id }
  lifecycle {
    precondition {
      condition     = length(var.inbound_pf_client_secret) >= 8
      error_message = "Set a dedicated inbound_pf_client_secret before provisioning."
    }
  }
}

resource "pingfederate_oauth_access_token_manager" "inbound_exchange" {
  count                 = var.create_inbound_entra_exchange_policy ? 1 : 0
  manager_id            = "brokerInboundATM"
  name                  = "Broker inbound exchange reference tokens"
  plugin_descriptor_ref = { id = local.reference_bearer_plugin }
  configuration         = { fields = local.reference_bearer_fields }
  attribute_contract    = { extended_attributes = local.broker_token_attributes }
  access_control_settings = {
    restrict_clients = true
    allowed_clients  = [{ id = pingfederate_oauth_client.inbound_exchange[0].client_id }, { id = pingfederate_oauth_client.broker.client_id }]
  }
}

resource "pingfederate_oauth_access_token_mapping" "inbound_exchange" {
  count                    = var.create_inbound_entra_exchange_policy ? 1 : 0
  context                  = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY", context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.inbound_entra[0].policy_id } }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.inbound_exchange[0].manager_id }
  attribute_contract_fulfillment = {
    sub                   = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "subject" }
    iss                   = { source = { type = "TEXT" }, value = var.pf_public_url }
    aud                   = { source = { type = "TEXT" }, value = var.broker_audience }
    broker_principal_type = { source = { type = "TEXT" }, value = "user" }
  }
}
