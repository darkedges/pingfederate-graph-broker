mock_provider "azuread" {
  mock_data "azuread_service_principal" {
    defaults = {
      oauth2_permission_scope_ids = {
        "User.ReadBasic.All"   = "11111111-1111-1111-1111-111111111111"
        "GroupMember.Read.All" = "22222222-2222-2222-2222-222222222222"
      }
    }
  }
}

mock_provider "pingfederate" {}

mock_provider "time" {}

variables {
  activate_clients         = false
  attach_pf_token_contract = false
  enable_dev_login         = false
  enable_local_pf_tls      = false
  activate_local_pf_tls    = false
  entra_tenant_id          = "11111111-1111-1111-1111-111111111111"
  pf_admin_url             = "https://localhost:9999"
  pf_public_url            = "https://localhost:9031"
  portal_redirect_uri      = "https://localhost:8788/auth/callback"
  broker_audience          = "https://broker.example.test"
  pf_portal_client_secret  = "fake-portal-secret"
  pf_agent_client_secret   = "fake-agent-secret"
  pf_broker_client_secret  = "fake-broker-secret"
}

run "scoped_clients_and_read_only_entra_app" {
  command = plan

  assert {
    condition = (
      azuread_application_registration.connector.sign_in_audience == "AzureADMyOrg" &&
      length(azuread_application_api_access.graph_reads.scope_ids) == 2 &&
      try(length(azuread_application_api_access.graph_reads.role_ids), 0) == 0
    )
    error_message = "The connector must request only the two delegated Graph read scopes."
  }

  assert {
    condition = (
      toset(pingfederate_oauth_client.portal.grant_types) == toset(["AUTHORIZATION_CODE", "REFRESH_TOKEN"]) &&
      toset(pingfederate_oauth_client.agent.grant_types) == toset(["CLIENT_CREDENTIALS"]) &&
      toset(pingfederate_oauth_client.broker.grant_types) == toset(["ACCESS_TOKEN_VALIDATION"]) &&
      pingfederate_oauth_client.portal.require_proof_key_for_code_exchange &&
      !pingfederate_oauth_client.portal.enabled &&
      !pingfederate_oauth_client.agent.enabled &&
      !pingfederate_oauth_client.broker.enabled
    )
    error_message = "PF clients must retain their distinct grant roles and portal PKCE."
  }

  assert {
    condition = (
      pingfederate_oauth_client.portal.default_access_token_manager_ref == null &&
      pingfederate_oauth_client.agent.default_access_token_manager_ref == null &&
      pingfederate_oauth_access_token_manager.user.access_control_settings.restrict_clients &&
      toset([for client in pingfederate_oauth_access_token_manager.user.access_control_settings.allowed_clients : client.id]) == toset(["directory-portal", "directory-broker-rs"])
    )
    error_message = "Bootstrap must create disabled clients first, without ATM references, while keeping ATMs restricted."
  }

  assert {
    condition     = length(pingfederate_sp_idp_connection.entra) == 0
    error_message = "Unreviewed PF handoff configuration must stay disabled."
  }

  assert {
    condition = (
      length(pingfederate_password_credential_validator.dev_login) == 0 &&
      length(pingfederate_idp_adapter.dev_login) == 0 &&
      length(pingfederate_oauth_idp_adapter_mapping.dev_login) == 0
    )
    error_message = "The dev-only login must remain disabled by default."
  }

  assert {
    condition = (
      length(pingfederate_keypairs_ssl_server_key.local_mkcert) == 0 &&
      length(pingfederate_keypairs_ssl_server_settings.local_mkcert) == 0
    )
    error_message = "The local PF certificate import and singleton activation must remain opt-in."
  }

  assert {
    condition = (
      pingfederate_oauth_access_token_mapping.user.attribute_contract_fulfillment["broker_principal_type"].value == "user" &&
      pingfederate_oauth_access_token_mapping.agent.attribute_contract_fulfillment["broker_principal_type"].value == "agent" &&
      pingfederate_oauth_access_token_mapping.user.attribute_contract_fulfillment["sub"].source.type == "OAUTH_PERSISTENT_GRANT"
    )
    error_message = "Managed token mappings must preserve a trusted user subject and distinct principal types."
  }
}

run "dev_login_uses_authenticated_adapter_identity" {
  command = plan

  variables {
    enable_dev_login      = true
    pf_dev_login_password = "fake-dev-password-123456"
  }

  assert {
    condition = (
      length(pingfederate_password_credential_validator.dev_login) == 1 &&
      length(pingfederate_idp_adapter.dev_login) == 1 &&
      length(pingfederate_oauth_idp_adapter_mapping.dev_login) == 1 &&
      contains([for table in pingfederate_password_credential_validator.dev_login[0].configuration.tables : table.name], "Users") &&
      pingfederate_oauth_idp_adapter_mapping.dev_login[0].attribute_contract_fulfillment["USER_KEY"].source.type == "ADAPTER" &&
      pingfederate_oauth_idp_adapter_mapping.dev_login[0].attribute_contract_fulfillment["USER_KEY"].value == "username"
    )
    error_message = "Dev login must use its dedicated PCV and authenticated adapter username for USER_KEY."
  }
}

run "dev_login_rejects_nonlocal_admin" {
  command = plan

  variables {
    enable_dev_login      = true
    pf_dev_login_password = "fake-dev-password-123456"
    pf_admin_url          = "https://pf.example.test:9999"
  }

  expect_failures = [pingfederate_password_credential_validator.dev_login]
}

run "attach_existing_pf_token_contract" {
  command = plan

  variables {
    attach_pf_token_contract = true
  }

  assert {
    condition = (
      pingfederate_oauth_client.portal.default_access_token_manager_ref.id == "brokerUserATM" &&
      pingfederate_oauth_client.agent.default_access_token_manager_ref.id == "brokerAgentATM" &&
      pingfederate_oauth_client.portal.oidc_policy.policy_group.id == "brokerPortalOIDC" &&
      !pingfederate_oauth_client.portal.enabled
    )
    error_message = "The second stage must attach the managed PF contract while clients remain disabled."
  }
}

run "reviewed_handoff_is_declarative" {
  command = plan

  variables {
    pf_handoff = {
      reference_adapter_plugin_id = "example.plugin.ReferenceAdapter"
      adapter_fields              = [{ name = "Target Application URL", value = "https://portal.example.test/auth/reference-callback" }]
      adapter_sensitive_fields    = [{ name = "Pickup Password", value = "fake-pickup-secret" }]
      idp_identity_mapping        = "ACCOUNT_MAPPING"
      attribute_fulfillment = {
        subject              = { source = { type = "CLAIMS" }, value = "sub" }
        entra_tid            = { source = { type = "CLAIMS" }, value = "tid" }
        entra_oid            = { source = { type = "CLAIMS" }, value = "oid" }
        entra_token_response = { source = { type = "CONTEXT" }, value = "tokenEndpointResponse" }
      }
    }
  }

  assert {
    condition     = length(pingfederate_sp_adapter.reference_id) == 1 && length(pingfederate_sp_idp_connection.entra) == 1
    error_message = "The reviewed PF adapter and OIDC IdP connection must be declared together."
  }

  assert {
    condition     = output.portal_connect_start_url_candidate == "https://localhost:9031/sp/startSSO.ping?PartnerIdpId=https%3A%2F%2Flogin.microsoftonline.com%2F11111111-1111-1111-1111-111111111111%2Fv2.0&SpSessionAuthnAdapterId=graphDirectoryLink"
    error_message = "The candidate portal journey URL must target the managed IdP connection and SP session adapter."
  }
}

run "dev_handoff_binds_one_validated_entra_identity" {
  command = plan

  variables {
    enable_dev_login       = true
    pf_dev_login_password  = "fake-dev-password-123456"
    enable_dev_handoff     = true
    pf_dev_link_entra_oid  = "33333333-3333-4333-8333-333333333333"
    pf_dev_pickup_password = "fake-pickup-password-123456"
  }

  assert {
    condition = (
      length(pingfederate_sp_adapter.reference_id) == 1 &&
      pingfederate_sp_adapter.reference_id[0].plugin_descriptor_ref.id == "com.pingidentity.pf.adapters.referenceid.SpBackchannelReferenceAuthnAdapter" &&
      pingfederate_sp_adapter.reference_id[0].adapter_id == "graphDirectoryLink" &&
      contains([for field in pingfederate_sp_adapter.reference_id[0].configuration.fields : "${field.name}=${field.value}"], "Transport Mode=2") &&
      contains([for field in pingfederate_sp_adapter.reference_id[0].configuration.fields : field.value], "https://localhost:8788/auth/reference-callback") &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.default_target_url == "https://localhost:8788/auth/reference-callback" &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["subject"].value == "broker-dev-user" &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["entra_tid"].source.type == "CLAIMS" &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["entra_oid"].source.type == "CLAIMS" &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["entra_token_response"].value == "tokenEndpointResponse" &&
      alltrue([for criterion in pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].issuance_criteria.conditional_criteria : criterion.source.type == "CLAIMS"]) &&
      toset([for criterion in pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].issuance_criteria.conditional_criteria : "${criterion.attribute_name}=${criterion.value}"]) == toset([
        "tid=11111111-1111-1111-1111-111111111111",
        "oid=33333333-3333-4333-8333-333333333333",
      ])
    )
    error_message = "The dev handoff must use the installed adapter and bind the local subject only after exact tenant and object-ID checks."
  }
}

run "dev_handoff_probe_replaces_only_token_response" {
  command = plan

  variables {
    enable_dev_login         = true
    pf_dev_login_password    = "fake-dev-password-123456"
    enable_dev_handoff       = true
    enable_dev_handoff_probe = true
    pf_dev_link_entra_oid    = "33333333-3333-4333-8333-333333333333"
    pf_dev_pickup_password   = "fake-pickup-password-123456"
  }

  assert {
    condition = (
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["entra_token_response"].source.type == "TEXT" &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["entra_token_response"].value == "PROBE_NO_TOKEN_RESPONSE" &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["subject"].value == "broker-dev-user" &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["entra_tid"].source.type == "CLAIMS" &&
      pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].attribute_contract_fulfillment["entra_oid"].source.type == "CLAIMS" &&
      toset([for criterion in pingfederate_sp_idp_connection.entra[0].idp_browser_sso.adapter_mappings[0].issuance_criteria.conditional_criteria : "${criterion.attribute_name}=${criterion.value}"]) == toset([
        "tid=11111111-1111-1111-1111-111111111111",
        "oid=33333333-3333-4333-8333-333333333333",
      ])
    )
    error_message = "The probe may replace only the token-response mapping; the subject and exact Entra identity checks must remain unchanged."
  }
}

run "handoff_probe_rejects_non_dev_configuration" {
  command = plan

  variables {
    enable_dev_handoff_probe = true
  }

  expect_failures = [var.enable_dev_handoff_probe]
}
