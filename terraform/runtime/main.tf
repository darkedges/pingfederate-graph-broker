terraform {
  required_version = ">= 1.9.0"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "= 4.6.0"
    }
  }
}

provider "docker" {}

# The Compose provider does not build the broker image before creating its
# container. Build the same image name Compose references, in this state.
resource "docker_image" "broker" {
  count        = var.start_broker ? 1 : 0
  name         = "pingfederate-graph-broker-broker:latest"
  keep_locally = true

  build {
    context    = abspath("${path.module}/../..")
    dockerfile = "Dockerfile"
  }

  lifecycle {
    precondition {
      # Canonical base64 of 32 bytes has 43 data characters and one '='.
      # This checks shape without putting the key in Terraform output/state.
      condition = can(regex(
        "(?m)^TOKEN_ENCRYPTION_KEY=[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=\\r?$",
        file("${path.module}/../../.env"),
      ))
      error_message = "Set TOKEN_ENCRYPTION_KEY in .env to base64 of exactly 32 random bytes before starting the broker. Keep the same key for stored connections."
    }
  }
}

# Runtime is a separate Terraform state so that PF is reachable before the
# PingFederate provider in ../ is configured. Compose remains the source of
# container settings; Terraform owns its lifecycle.
resource "docker_compose" "broker_stack" {
  project_name      = "pingfederate-graph-broker"
  project_directory = abspath("${path.module}/../..")
  config_paths      = [abspath("${path.module}/../../compose.yaml")]
  env_files         = [abspath("${path.module}/../../.env")]
  profiles          = var.start_broker ? ["broker"] : []
  wait              = true
  wait_timeout      = "10m"
  depends_on        = [docker_image.broker]

  lifecycle {
    precondition {
      condition     = fileexists("${path.module}/../../.env")
      error_message = "Create .env from .env.example and supply secrets before managing runtime containers."
    }
    precondition {
      condition     = !var.start_broker || fileexists("${path.module}/../../certs/ca/mkcert-rootCA.pem")
      error_message = "Copy mkcert's public rootCA.pem to certs/ca/mkcert-rootCA.pem before starting the broker; TLS verification must remain enabled."
    }
  }
}

variable "start_broker" {
  description = "Start the broker after the Entra/PF identity resources and .env values are configured."
  type        = bool
  default     = false
}

output "compose_project" {
  value = docker_compose.broker_stack.id
}
