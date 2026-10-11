# Request only the existing custom API's delegated access_as_user permission.
# This does not modify the API registration or grant Graph write permissions.
data "azuread_service_principal" "inbound_api" {
  provider  = azuread.inbound
  count     = var.create_inbound_entra_exchange_policy ? 1 : 0
  client_id = "e83c2af3-43d1-4f62-8bff-e619c29b5026"
}

variable "inbound_portal_redirect_uri" {
  type    = string
  default = "https://portal.entraid.darkedges.com/auth/entra/callback"
  validation {
    condition     = can(regex("^https://[^/?#]+/auth/entra/callback$", var.inbound_portal_redirect_uri))
    error_message = "Use an exact HTTPS portal /auth/entra/callback URI."
  }
}

resource "azuread_application_registration" "inbound_exchange" {
  provider         = azuread.inbound
  count            = var.create_inbound_entra_exchange_policy ? 1 : 0
  display_name     = "Directory broker Entra-to-PF exchange"
  sign_in_audience = "AzureADMyOrg"
}
resource "azuread_service_principal" "inbound_exchange" {
  provider  = azuread.inbound
  count     = var.create_inbound_entra_exchange_policy ? 1 : 0
  client_id = azuread_application_registration.inbound_exchange[0].client_id
}
resource "azuread_application_api_access" "inbound_exchange" {
  provider       = azuread.inbound
  count          = var.create_inbound_entra_exchange_policy ? 1 : 0
  application_id = azuread_application_registration.inbound_exchange[0].id
  api_client_id  = data.azuread_service_principal.inbound_api[0].client_id
  scope_ids      = [data.azuread_service_principal.inbound_api[0].oauth2_permission_scope_ids["access_as_user"]]
}
resource "azuread_application_redirect_uris" "inbound_exchange" {
  provider       = azuread.inbound
  count          = var.create_inbound_entra_exchange_policy ? 1 : 0
  application_id = azuread_application_registration.inbound_exchange[0].id
  type           = "Web"
  redirect_uris  = [var.inbound_portal_redirect_uri]
}
resource "azuread_application_password" "inbound_exchange" {
  provider       = azuread.inbound
  count          = var.create_inbound_entra_exchange_policy ? 1 : 0
  application_id = azuread_application_registration.inbound_exchange[0].id
  display_name   = "Broker inbound code redemption"
  end_date       = timeadd(time_static.connector_secret_issued.rfc3339, "4320h")
}
output "inbound_entra_client_id" {
  value = try(azuread_application_registration.inbound_exchange[0].client_id, null)
}
output "inbound_entra_client_secret" {
  value     = try(azuread_application_password.inbound_exchange[0].value, null)
  sensitive = true
}
