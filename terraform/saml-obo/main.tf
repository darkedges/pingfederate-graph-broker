terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "= 3.9.0"
    }
  }
}

variable "tenant_id" {
  type    = string
  default = "4161be3f-bf2b-41d4-a02b-e6f82b529d53"
}

variable "saml_client_id" {
  type    = string
  default = "edd9f241-d550-4de8-845d-3fa299090014"
}

variable "secret_expires_at" {
  description = "UTC expiry for the dedicated OBO app secret; rotate before this date."
  type        = string
  default     = "2027-10-01T00:00:00Z"
}

provider "azuread" {
  tenant_id = var.tenant_id
}

locals {
  graph_client_id = "00000003-0000-0000-c000-000000000000"
}

data "azuread_service_principal" "graph" {
  client_id = local.graph_client_id
}

# This is a new middle-tier API. Do not attach these permissions to the existing
# broad-permission token-exchange app; its Graph grants are left untouched.
resource "azuread_application_registration" "broker_obo" {
  display_name                   = "Directory broker read-only SAML OBO"
  sign_in_audience               = "AzureADMyOrg"
  requested_access_token_version = 2
}

resource "azuread_application_identifier_uri" "broker_obo" {
  application_id = azuread_application_registration.broker_obo.id
  identifier_uri = "api://${azuread_application_registration.broker_obo.client_id}"
}

resource "azuread_application_permission_scope" "access_as_user" {
  application_id             = azuread_application_registration.broker_obo.id
  scope_id                   = "77fd1ff6-6f3f-498b-b439-daf5e45bebe0"
  value                      = "access_as_user"
  type                       = "Admin"
  admin_consent_display_name = "Access the directory broker as the signed-in user"
  admin_consent_description  = "Allow the PingFederate SAML exchange client to access the directory broker on behalf of the signed-in user."
}

resource "azuread_application_pre_authorized" "saml_client" {
  application_id       = azuread_application_registration.broker_obo.id
  authorized_client_id = var.saml_client_id
  permission_ids       = [azuread_application_permission_scope.access_as_user.scope_id]
}

resource "azuread_application_api_access" "graph_reads" {
  application_id = azuread_application_registration.broker_obo.id
  api_client_id  = local.graph_client_id
  scope_ids = [
    data.azuread_service_principal.graph.oauth2_permission_scope_ids["User.ReadBasic.All"],
    data.azuread_service_principal.graph.oauth2_permission_scope_ids["GroupMember.Read.All"],
  ]
}

resource "azuread_service_principal" "broker_obo" {
  client_id = azuread_application_registration.broker_obo.client_id
}

# Admin consent for only the two delegated read scopes. No application roles.
resource "azuread_service_principal_delegated_permission_grant" "graph_reads" {
  service_principal_object_id          = azuread_service_principal.broker_obo.object_id
  resource_service_principal_object_id = data.azuread_service_principal.graph.object_id
  claim_values                         = ["User.ReadBasic.All", "GroupMember.Read.All"]
}

resource "azuread_application_password" "broker_obo" {
  application_id = azuread_application_registration.broker_obo.id
  display_name   = "directory-broker-saml-obo"
  end_date       = var.secret_expires_at
}

output "client_id" {
  value = azuread_application_registration.broker_obo.client_id
}

output "scope" {
  value = "${azuread_application_identifier_uri.broker_obo.identifier_uri}/${azuread_application_permission_scope.access_as_user.value}"
}

output "client_secret" {
  value     = azuread_application_password.broker_obo.value
  sensitive = true
}
