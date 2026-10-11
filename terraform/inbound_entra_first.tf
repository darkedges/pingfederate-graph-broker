# Separate from the existing actor-required policy. Nothing changes its rules.
variable "activate_inbound_clients" {
  type        = bool
  default     = false
  description = "Enable inbound clients and attach their ATMs after the initial disabled-client/ATM provisioning apply."
}
variable "create_inbound_entra_first_policy" {
  type    = bool
  default = false
}

variable "inbound_first_pf_client_secret" {
  type      = string
  default   = ""
  sensitive = true
}

resource "pingfederate_oauth_token_exchange_processor_policy" "inbound_first" {
  count                = var.create_inbound_entra_first_policy ? 1 : 0
  policy_id            = "brokerEntraFirstPolicy"
  name                 = "Broker Entra-first metadata exchange"
  actor_token_required = false
  processor_mappings = [{
    subject_token_type      = "urn:ietf:params:oauth:token-type:access_token:msft"
    subject_token_processor = { id = try(pingfederate_idp_token_processor.inbound_microsoft[0].processor_id, "") }
    attribute_contract_fulfillment = {
      subject = { source = { type = "TEXT" }, value = var.pf_saml_expected_subject }
    }
    issuance_criteria = {
      conditional_criteria = [
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "tid", condition = "EQUALS", value = local.inbound_tenant_id },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "oid", condition = "EQUALS", value = var.inbound_entra_object_id },
        { source = { type = "SUBJECT_TOKEN" }, attribute_name = "scp", condition = "EQUALS", value = "access_as_user" },
      ]
    }
  }]
  lifecycle {
    precondition {
      condition     = var.create_inbound_entra_exchange_policy && trimspace(var.pf_saml_expected_subject) != ""
      error_message = "Enable create_inbound_entra_exchange_policy for the shared Microsoft processor and Entra application, and configure the canonical PF subject."
    }
  }
}

resource "pingfederate_oauth_client" "inbound_first" {
  count                                    = var.create_inbound_entra_first_policy ? 1 : 0
  client_id                                = "directory-entra-first"
  name                                     = "Broker Entra-first inspection only"
  enabled                                  = var.activate_inbound_clients
  client_auth                              = { type = "SECRET", secret = var.inbound_first_pf_client_secret }
  grant_types                              = ["TOKEN_EXCHANGE"]
  restricted_scopes                        = var.inbound_first_jwt ? ["broker.connect", "openid"] : ["broker.connect"]
  oidc_policy                              = var.inbound_first_jwt ? { policy_group = { id = "brokerEntraOIDC" } } : null
  restrict_scopes                          = true
  default_access_token_manager_ref         = var.activate_inbound_clients ? { id = var.inbound_first_jwt ? "brokerEntraJWT" : "brokerEntraFirstATM" } : null
  restrict_to_default_access_token_manager = var.activate_inbound_clients
  token_exchange_processor_policy_ref      = { id = pingfederate_oauth_token_exchange_processor_policy.inbound_first[0].policy_id }
  lifecycle {
    precondition {
      condition     = length(var.inbound_first_pf_client_secret) >= 8
      error_message = "Set a dedicated inbound_first_pf_client_secret (at least eight characters)."
    }
  }
}

resource "pingfederate_oauth_access_token_manager" "inbound_first" {
  count                 = var.create_inbound_entra_first_policy ? 1 : 0
  manager_id            = "brokerEntraFirstATM"
  name                  = "Broker Entra-first inspection reference tokens"
  plugin_descriptor_ref = { id = local.reference_bearer_plugin }
  configuration         = { fields = local.reference_bearer_fields }
  attribute_contract    = { extended_attributes = local.broker_token_attributes }
  access_control_settings = {
    restrict_clients = true
    allowed_clients  = [{ id = pingfederate_oauth_client.inbound_first[0].client_id }, { id = pingfederate_oauth_client.broker.client_id }]
  }
}

resource "pingfederate_oauth_access_token_mapping" "inbound_first" {
  count                    = var.create_inbound_entra_first_policy ? 1 : 0
  context                  = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY", context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.inbound_first[0].policy_id } }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.inbound_first[0].manager_id }
  attribute_contract_fulfillment = {
    sub                   = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "subject" }
    iss                   = { source = { type = "TEXT" }, value = var.pf_public_url }
    aud                   = { source = { type = "TEXT" }, value = var.broker_audience }
    broker_principal_type = { source = { type = "TEXT" }, value = "user" }
  }
}
