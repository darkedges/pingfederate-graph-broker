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
  description = "Trusted local PingFederate administrative API URL."
  type        = string
  default     = "https://localhost:9999"
  validation {
    condition     = can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_admin_url))
    error_message = "Manage this dev instance through its local HTTPS admin API only."
  }
}

variable "public_pf_hostname" {
  description = "Browser-facing PingFederate runtime hostname served by the tunnel."
  type        = string
  default     = "ping.entraid.darkedges.com"
  validation {
    condition     = var.public_pf_hostname == "ping.entraid.darkedges.com"
    error_message = "This local tunnel configuration is pinned to ping.entraid.darkedges.com."
  }
}

provider "pingfederate" {
  https_host      = var.pf_admin_url
  product_version = "13.1"
}

# Adopt the existing singleton and retain every existing virtual hostname.
# This is separate from the main PF/Entra state to avoid unrelated changes.
data "pingfederate_virtual_host_names" "existing" {}

resource "pingfederate_virtual_host_names" "public_pf" {
  virtual_host_names = toset(concat(
    tolist(coalesce(data.pingfederate_virtual_host_names.existing.virtual_host_names, toset([]))),
    [var.public_pf_hostname],
  ))

  lifecycle {
    prevent_destroy = true
  }
}

import {
  to = pingfederate_virtual_host_names.public_pf
  id = "id"
}
