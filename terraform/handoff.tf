# The generic handoff remains opt-in and instance-specific. The separate
# dev-only branch uses the installed Agentless 2.3.1 SP adapter class and
# allows one exact Entra tenant/object ID to map to broker-dev-user. PF must
# enforce both issuance criteria before emitting a Reference ID. The browser
# and its request parameters never supply the subject or Entra identity.
locals {
  pf_handoff_enabled            = var.enable_dev_handoff || var.pf_handoff != null
  pf_dev_reference_callback_url = var.pf_dev_reference_callback_url != null ? var.pf_dev_reference_callback_url : "${trimsuffix(var.portal_redirect_uri, "/auth/callback")}/auth/reference-callback"
  pf_dev_adapter_fields = [
    { name = "Authentication Endpoint", value = local.pf_dev_reference_callback_url },
    { name = "User Name", value = var.pf_dev_pickup_username },
    { name = "Reference Duration", value = "60" },
    { name = "Reference Length", value = "30" },
    { name = "Require SSL/TLS", value = "true" },
    # The Agentless 2.3.1 plugin displays "Form Post" but stores option value "2".
    { name = "Transport Mode", value = "2" },
    { name = "Outgoing Attribute Format", value = "JSON" },
  ]
  # Diagnostic only: distinguish an adapter problem with a complex context
  # value from a failure elsewhere in the handoff. This cannot create a broker
  # connection: the broker rejects the marker as an invalid token response.
  pf_dev_token_response_fulfillment = var.enable_dev_handoff_probe ? {
    source = { type = "TEXT" }
    value  = "PROBE_NO_TOKEN_RESPONSE"
    } : {
    source = { type = "CONTEXT" }
    value  = "tokenEndpointResponse"
  }
  pf_dev_attribute_fulfillment = {
    subject   = { source = { type = "TEXT" }, value = "broker-dev-user" }
    entra_tid = { source = { type = "CLAIMS" }, value = "tid" }
    entra_oid = { source = { type = "CLAIMS" }, value = "oid" }
    # The Admin API prepends "context." to the normal value during validation.
    entra_token_response = local.pf_dev_token_response_fulfillment
  }
}

resource "pingfederate_sp_adapter" "reference_id" {
  count      = local.pf_handoff_enabled ? 1 : 0
  adapter_id = "graphDirectoryLink"
  name       = "Directory broker Reference ID handoff"

  plugin_descriptor_ref = {
    id = var.enable_dev_handoff ? var.pf_dev_reference_adapter_plugin_id : var.pf_handoff.reference_adapter_plugin_id
  }

  configuration = {
    fields           = var.enable_dev_handoff ? local.pf_dev_adapter_fields : var.pf_handoff.adapter_fields
    sensitive_fields = var.enable_dev_handoff ? [{ name = "Pass Phrase", value = var.pf_dev_pickup_password }] : var.pf_handoff.adapter_sensitive_fields
  }

  attribute_contract = {
    extended_attributes = [
      { name = "entra_tid" },
      { name = "entra_oid" },
      { name = "entra_token_response", masked = true },
    ]
  }

  lifecycle {
    precondition {
      condition = !var.enable_dev_handoff || (
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?/auth/callback$", var.portal_redirect_uri)) &&
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_admin_url)) &&
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_public_url))
      )
      error_message = "The dev handoff requires localhost PF and local portal OAuth URLs; a public Reference ID callback must match the additional portal origin."
    }
    precondition {
      condition     = !var.enable_dev_handoff || (var.pf_dev_link_entra_oid != null && try(length(var.pf_dev_pickup_password) >= 8, false))
      error_message = "Set pf_dev_link_entra_oid and a private TF_VAR_pf_dev_pickup_password of at least 8 characters before enabling the dev handoff."
    }
  }
}

resource "pingfederate_sp_idp_connection" "entra" {
  count         = local.pf_handoff_enabled ? 1 : 0
  connection_id = "entra-directory-link"
  name          = "Entra delegated directory link"
  entity_id     = "https://login.microsoftonline.com/${var.entra_tenant_id}/v2.0"
  active        = true

  oidc_client_credentials = {
    client_id     = azuread_application_registration.connector.client_id
    client_secret = azuread_application_password.connector.value
  }

  idp_browser_sso = {
    protocol             = "OIDC"
    idp_identity_mapping = var.enable_dev_handoff ? "ACCOUNT_MAPPING" : var.pf_handoff.idp_identity_mapping
    # PF automatically allows a connection's default target URL through SSO
    # redirect validation. Keep this scoped to the one localhost dev callback;
    # do not relax the server-wide redirect allowlist.
    default_target_url = var.enable_dev_handoff ? local.pf_dev_reference_callback_url : null

    oidc_provider_settings = {
      authorization_endpoint = "https://login.microsoftonline.com/${var.entra_tenant_id}/oauth2/v2.0/authorize"
      token_endpoint         = "https://login.microsoftonline.com/${var.entra_tenant_id}/oauth2/v2.0/token"
      jwks_url               = "https://login.microsoftonline.com/${var.entra_tenant_id}/discovery/v2.0/keys"
      login_type             = "CODE"
      authentication_scheme  = "POST"
      enable_pkce            = true
      scopes                 = "openid profile offline_access https://graph.microsoft.com/User.ReadBasic.All https://graph.microsoft.com/GroupMember.Read.All"
    }

    attribute_contract = {
      extended_attributes = [
        { name = "tid", masked = false },
        { name = "oid", masked = false },
      ]
    }

    adapter_mappings = [{
      sp_adapter_ref                 = { id = pingfederate_sp_adapter.reference_id[0].id }
      attribute_contract_fulfillment = var.enable_dev_handoff ? local.pf_dev_attribute_fulfillment : var.pf_handoff.attribute_fulfillment
      issuance_criteria = var.enable_dev_handoff ? {
        conditional_criteria = [
          {
            source         = { type = "CLAIMS" }
            attribute_name = "tid"
            condition      = "EQUALS_CASE_INSENSITIVE"
            value          = var.entra_tenant_id
          },
          {
            source         = { type = "CLAIMS" }
            attribute_name = "oid"
            condition      = "EQUALS_CASE_INSENSITIVE"
            value          = var.pf_dev_link_entra_oid
          },
        ]
      } : null
    }]
  }
}
