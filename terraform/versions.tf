terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "= 3.9.0"
    }
    pingfederate = {
      source  = "pingidentity/pingfederate"
      version = "= 1.9.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "= 0.14.2"
    }
  }
}

provider "azuread" {
  tenant_id = var.entra_tenant_id
}

# Set PINGFEDERATE_PROVIDER_USERNAME and PINGFEDERATE_PROVIDER_PASSWORD in
# the Terraform runner's environment. Trust the PF admin certificate via the
# system trust store or PINGFEDERATE_PROVIDER_CA_CERTIFICATE_PEM_FILES.
provider "pingfederate" {
  https_host      = var.pf_admin_url
  product_version = "13.1"
}
