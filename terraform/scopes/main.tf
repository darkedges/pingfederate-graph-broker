terraform {
  required_version = ">= 1.9.0"

  required_providers {
    pingfederate = {
      source  = "pingidentity/pingfederate"
      version = "= 1.9.0"
    }
  }
}

variable "pf_admin_url" {
  description = "Trusted PingFederate administrative API URL."
  type        = string
  default     = "https://localhost:9999"
  validation {
    condition     = startswith(var.pf_admin_url, "https://")
    error_message = "PingFederate administration requires HTTPS."
  }
}

provider "pingfederate" {
  https_host      = var.pf_admin_url
  product_version = "13.1"
}

# PF stores scopes in its global OAuth-server settings, not on individual
# client resources. Read the existing singleton so profile/tenant scopes are
# retained. This root must be the only Terraform owner of that singleton.
data "pingfederate_oauth_server_settings" "existing" {}

locals {
  broker_scopes = [
    { name = "broker.connect", description = "Connect a user's Microsoft directory through the broker", dynamic = false },
    { name = "broker.directory.read", description = "Use an assigned read-only directory delegation", dynamic = false },
  ]
  existing_scope_names = toset([for scope in data.pingfederate_oauth_server_settings.existing.scopes : scope.name])
  preserved_scopes = [for scope in data.pingfederate_oauth_server_settings.existing.scopes : {
    name        = scope.name
    description = scope.description
    dynamic     = scope.dynamic
  }]
  missing_broker_scopes = [for scope in local.broker_scopes : scope if !contains(local.existing_scope_names, scope.name)]
}

resource "pingfederate_oauth_server_settings" "broker_scopes" {
  authorization_code_entropy = data.pingfederate_oauth_server_settings.existing.authorization_code_entropy
  authorization_code_timeout = data.pingfederate_oauth_server_settings.existing.authorization_code_timeout
  refresh_rolling_interval   = data.pingfederate_oauth_server_settings.existing.refresh_rolling_interval
  refresh_token_length       = data.pingfederate_oauth_server_settings.existing.refresh_token_length

  scopes = concat(local.preserved_scopes, local.missing_broker_scopes)

  lifecycle {
    prevent_destroy = true
    precondition {
      condition = length(setintersection(
        toset([for scope in data.pingfederate_oauth_server_settings.existing.exclusive_scopes : scope.name]),
        toset([for scope in local.broker_scopes : scope.name])
      )) == 0
      error_message = "A broker scope already exists as an exclusive scope. Review the existing PF configuration before continuing."
    }
  }
}

# The settings already exist in PF. Import them before any update so Terraform
# presents a diff instead of treating this singleton as a new resource.
import {
  to = pingfederate_oauth_server_settings.broker_scopes
  id = "id"
}
