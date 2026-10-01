locals {
  graph_app_id = "00000003-0000-0000-c000-000000000000"
}

# These are delegated Graph permissions. The connector has no application roles
# and no directory write permissions.
data "azuread_service_principal" "graph" {
  client_id = local.graph_app_id
}

resource "azuread_application_registration" "connector" {
  display_name     = var.entra_app_display_name
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_application_api_access" "graph_reads" {
  application_id = azuread_application_registration.connector.id
  api_client_id  = local.graph_app_id
  scope_ids = [
    data.azuread_service_principal.graph.oauth2_permission_scope_ids["User.ReadBasic.All"],
    data.azuread_service_principal.graph.oauth2_permission_scope_ids["GroupMember.Read.All"],
  ]
}

# PF computes a per-connection callback. Register that exact Web URI only after
# the OIDC IdP connection exists; never guess a /sp/.../cb.openid path.
resource "azuread_application_redirect_uris" "pf_oidc" {
  count          = local.pf_handoff_enabled ? 1 : 0
  application_id = azuread_application_registration.connector.id
  type           = "Web"
  redirect_uris = compact([
    pingfederate_sp_idp_connection.entra[0].idp_browser_sso.oidc_provider_settings.redirect_uri,
    var.pf_oidc_public_redirect_uri,
  ])
}

resource "azuread_service_principal" "connector" {
  client_id = azuread_application_registration.connector.client_id
}

# The same confidential client is used by PF for the code exchange and by the
# broker for refresh. Its generated value is sensitive but still resides in TF
# state, so use encrypted access-controlled state before applying.
resource "time_static" "connector_secret_issued" {}

resource "azuread_application_password" "connector" {
  application_id = azuread_application_registration.connector.id
  display_name   = "pingfederate-graph-broker"
  end_date       = timeadd(time_static.connector_secret_issued.rfc3339, "4320h")
}

resource "pingfederate_oauth_client" "portal" {
  client_id = "directory-portal"
  name      = "Directory broker portal"
  enabled   = var.activate_clients

  client_auth = {
    type   = "SECRET"
    secret = var.pf_portal_client_secret
  }

  grant_types                         = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  redirect_uris                       = compact([var.portal_redirect_uri, var.portal_additional_redirect_uri])
  require_proof_key_for_code_exchange = true
  restrict_scopes                     = true
  restricted_scopes                   = ["broker.connect"]
  # Use the stable PF ID rather than a Terraform resource reference so the
  # clients can be created before the ATMs that allowlist them.
  default_access_token_manager_ref         = var.attach_pf_token_contract ? { id = "brokerUserATM" } : null
  restrict_to_default_access_token_manager = true

  oidc_policy = var.attach_pf_token_contract ? {
    policy_group              = { id = "brokerPortalOIDC" }
    post_logout_redirect_uris = [for uri in compact([var.portal_redirect_uri, var.portal_additional_redirect_uri]) : "${trimsuffix(uri, "/auth/callback")}/"]
  } : null

  lifecycle {
    precondition {
      condition     = !var.activate_clients || var.attach_pf_token_contract
      error_message = "Attach the PF token contract before activating OAuth clients."
    }
  }
}

resource "pingfederate_oauth_client" "agent" {
  client_id = "directory-agent"
  name      = "Directory broker agent"
  enabled   = var.activate_clients

  client_auth = {
    type   = "SECRET"
    secret = var.pf_agent_client_secret
  }

  grant_types                              = ["CLIENT_CREDENTIALS"]
  restrict_scopes                          = true
  restricted_scopes                        = ["broker.directory.read"]
  default_access_token_manager_ref         = var.attach_pf_token_contract ? { id = "brokerAgentATM" } : null
  restrict_to_default_access_token_manager = true

  lifecycle {
    precondition {
      condition     = !var.activate_clients || var.attach_pf_token_contract
      error_message = "Attach the PF token contract before activating OAuth clients."
    }
  }
}

resource "pingfederate_oauth_client" "broker" {
  client_id = "directory-broker-rs"
  name      = "Directory broker introspection"
  enabled   = var.activate_clients

  client_auth = {
    type   = "SECRET"
    secret = var.pf_broker_client_secret
  }

  grant_types                      = ["ACCESS_TOKEN_VALIDATION"]
  validate_using_all_eligible_atms = true

  lifecycle {
    precondition {
      condition     = !var.activate_clients || var.attach_pf_token_contract
      error_message = "Attach the PF token contract before activating OAuth clients."
    }
  }
}
