output "entra_connector_client_id" {
  description = "Set ENTRA_CLIENT_ID to this value in the broker."
  value       = azuread_application_registration.connector.client_id
}

output "entra_connector_client_secret" {
  description = "Deliver this to PF and the broker using a secret manager; never put it in version control."
  value       = azuread_application_password.connector.value
  sensitive   = true
}

output "broker_client_ids" {
  value = {
    portal = pingfederate_oauth_client.portal.client_id
    agent  = pingfederate_oauth_client.agent.client_id
    broker = pingfederate_oauth_client.broker.client_id
  }
}

output "saml_exchange_client_id" {
  description = "Local PF client ID for SAML exchange; enabling the client alone does not configure token processing or generation."
  value       = pingfederate_oauth_client.saml_exchange.client_id
}

output "saml_processor_policy_id" {
  description = "Staged local reference-token processor policy ID, if created. This policy is not yet attached to the exchange client."
  value       = try(pingfederate_oauth_token_exchange_processor_policy.broker_user[0].policy_id, null)
}

output "saml_signing_key" {
  description = "Public metadata of the unused local SAML signing key. Does not configure Entra trust or reveal private key material."
  value = var.create_saml_signing_key ? {
    id                 = pingfederate_keypairs_signing_key.broker_saml[0].key_id
    sha256_fingerprint = pingfederate_keypairs_signing_key.broker_saml[0].sha256_fingerprint
  } : null
}

output "saml_existing_signing_key" {
  description = "Read-only metadata for the imported, Entra-trusted MSFT11 signing key. Private key material is not in Terraform state."
  value = {
    id                 = data.pingfederate_keypairs_signing_key.msft11_local.key_id
    sha256_fingerprint = data.pingfederate_keypairs_signing_key.msft11_local.sha256_fingerprint
  }
}

output "saml_exchange_client_secret" {
  description = "PF exchange client secret supplied by the operator. Store privately; it is also held in Terraform state."
  value       = var.pf_saml_client_secret
  sensitive   = true
}

output "pf_entra_connection_id" {
  description = "Created when pf_handoff has a reviewed adapter and mapping."
  value       = try(pingfederate_sp_idp_connection.entra[0].connection_id, null)
}

output "portal_connect_start_url_candidate" {
  description = "Proposed PF SP-initiated SSO URL after the reviewed Entra handoff exists. Verify it against PF's Summary & Activation page and routing policy before setting PORTAL_PF_CONNECT_START_URL."
  value = local.pf_handoff_enabled ? format(
    "%s/sp/startSSO.ping?PartnerIdpId=%s&SpSessionAuthnAdapterId=%s",
    var.pf_public_url,
    # /sp/startSSO.ping resolves PartnerIdpId by the partner's entity ID.
    # The local Admin API connection ID is not a valid value here.
    urlencode(pingfederate_sp_idp_connection.entra[0].entity_id),
    urlencode(pingfederate_sp_adapter.reference_id[0].adapter_id),
  ) : null
}

output "dev_login" {
  description = "Local test-user and adapter IDs when enable_dev_login is true. The password is never output."
  value = var.enable_dev_login ? {
    username            = "broker-dev-user"
    additional_username = var.enable_dev_second_login ? "nirving@ping.darkedges.com" : null
    adapter_id          = pingfederate_idp_adapter.dev_login[0].adapter_id
  } : null
}

output "local_pf_tls_certificate_id" {
  description = "PF SSL server key ID after the opt-in localhost mkcert import. Does not include key material."
  value       = try(pingfederate_keypairs_ssl_server_key.local_mkcert[0].key_id, null)
}

output "configured_endpoints" {
  description = "Input endpoints to verify against the broker environment and PF introspection; these outputs do not configure the token contract."
  value = {
    pf_public_url       = var.pf_public_url
    portal_redirect_uri = var.portal_redirect_uri
    broker_audience     = var.broker_audience
  }
}
