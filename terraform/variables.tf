variable "entra_tenant_id" {
  description = "Entra tenant GUID for the dedicated single-tenant connector app."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", var.entra_tenant_id))
    error_message = "Enter an Entra tenant GUID."
  }
}

variable "pf_admin_url" {
  description = "Trusted HTTPS URL of the PingFederate administrative API host, usually port 9999."
  type        = string
  validation {
    condition     = startswith(var.pf_admin_url, "https://")
    error_message = "PingFederate administration requires an HTTPS URL."
  }
}

variable "pf_public_url" {
  description = "Public HTTPS base URL of the PingFederate runtime (no trailing slash)."
  type        = string
  validation {
    condition     = startswith(var.pf_public_url, "https://") && !endswith(var.pf_public_url, "/")
    error_message = "Use an HTTPS PingFederate runtime URL without a trailing slash."
  }
}

variable "portal_redirect_uri" {
  description = "Exact callback used by the portal's PF authorization-code client. HTTP is allowed only for loopback development."
  type        = string
  validation {
    condition     = startswith(var.portal_redirect_uri, "https://") || can(regex("^http://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?/", var.portal_redirect_uri))
    error_message = "Use HTTPS or an HTTP loopback URI for local development."
  }
}

variable "portal_additional_redirect_uri" {
  description = "Optional second exact HTTPS portal callback, for a public tunnel; preserves the local callback."
  type        = string
  default     = null
  validation {
    condition     = var.portal_additional_redirect_uri == null || can(regex("^https://[^/?#]+/auth/callback$", var.portal_additional_redirect_uri))
    error_message = "Use an exact HTTPS /auth/callback URI for the additional portal redirect."
  }
}

variable "pf_dev_reference_callback_url" {
  description = "Optional exact public HTTPS Reference ID POST callback for the one-user dev handoff. Must share the origin of portal_additional_redirect_uri."
  type        = string
  default     = null
  validation {
    condition = var.pf_dev_reference_callback_url == null || (
      var.portal_additional_redirect_uri != null &&
      var.pf_dev_reference_callback_url == "${trimsuffix(var.portal_additional_redirect_uri, "/auth/callback")}/auth/reference-callback"
    )
    error_message = "The public Reference ID callback must be /auth/reference-callback on the configured additional portal origin."
  }
}

variable "pf_oidc_public_redirect_uri" {
  description = "Exact public PingFederate OIDC callback observed in the Entra authorization request; preserve the PF-computed local callback."
  type        = string
  default     = null
  validation {
    condition     = var.pf_oidc_public_redirect_uri == null || can(regex("^https://[^/?#]+/sp/[A-Za-z0-9_-]+/cb[.]openid$", var.pf_oidc_public_redirect_uri))
    error_message = "Use the exact HTTPS PingFederate /sp/.../cb.openid callback, without query or fragment."
  }
}

variable "broker_audience" {
  description = "Audience returned by PF introspection for broker access tokens."
  type        = string
  validation {
    condition     = startswith(var.broker_audience, "https://")
    error_message = "Use an HTTPS broker audience."
  }
}

variable "pf_portal_client_secret" {
  description = "Secret for the confidential PF portal client; supply through TF_VAR_ or a secret manager."
  type        = string
  sensitive   = true
}

variable "pf_agent_client_secret" {
  description = "Secret for the PF agent client; supply through TF_VAR_ or a secret manager."
  type        = string
  sensitive   = true
}

variable "pf_broker_client_secret" {
  description = "Secret the broker uses to introspect PF access tokens."
  type        = string
  sensitive   = true
}

variable "pf_saml_client_secret" {
  description = "Secret for the localhost PF SAML token-exchange client. Supply privately in terraform.tfvars or TF_VAR_pf_saml_client_secret; it enters Terraform state."
  type        = string
  sensitive   = true
  validation {
    condition     = nonsensitive(length(var.pf_saml_client_secret) >= 8)
    error_message = "The SAML exchange client secret must be at least 8 characters."
  }
}

variable "enable_saml_exchange_client" {
  description = "Enable the localhost PF SAML token-exchange client only after its dedicated exchange policy, per-user mapping, and read-only Entra OBO consent are verified."
  type        = bool
  default     = false
}

variable "create_saml_processor_policy" {
  description = "Stage a localhost-only processor and policy for broker user reference tokens. This does not attach the policy to the OAuth client or configure SAML generation."
  type        = bool
  default     = false
}

variable "create_saml_signing_key" {
  description = "Create a new, initially unused RSA signing key in localhost PF for the SAML exchange. This does not modify Entra federation trust or select the key for a generator."
  type        = bool
  default     = false
}

variable "stage_msft11_generator" {
  description = "Stage a localhost SAML 1.1 generator using the fingerprint-pinned imported key. This does not attach a token-generator mapping or change Entra."
  type        = bool
  default     = false
}

variable "stage_msft11_mapping" {
  description = "Create the localhost-only one-user policy-to-MSFT11 mapping. Does not attach the policy to the exchange client."
  type        = bool
  default     = false
  validation {
    condition     = !var.stage_msft11_mapping || (var.stage_msft11_generator && var.create_saml_processor_policy)
    error_message = "The MSFT11 mapping requires the staged generator and one-user processor policy."
  }
}

variable "stage_msft11_generator_group" {
  description = "Set the localhost default token-exchange generator group to the dedicated SAML 1.1 generator. Refuses to overwrite another default group."
  type        = bool
  default     = false
  validation {
    condition     = !var.stage_msft11_generator_group || (var.stage_msft11_generator && var.stage_msft11_mapping)
    error_message = "The SAML 1.1 generator group requires the staged generator and one-user mapping."
  }
}

variable "pf_saml_entra_upn" {
  description = "Approved one-user Entra UPN for the local SAML mapping; not used for account linking."
  type        = string
  default     = null
  validation {
    condition     = !var.stage_msft11_mapping || (var.pf_saml_entra_upn != null && can(regex("^[^@ ]+@[^@ ]+$", var.pf_saml_entra_upn)))
    error_message = "Set an approved Entra UPN before staging the MSFT11 mapping."
  }
}

variable "pf_saml_immutable_id" {
  description = "Approved per-user Entra ImmutableID/NameID for the local SAML mapping."
  type        = string
  default     = null
  validation {
    condition     = !var.stage_msft11_mapping || (var.pf_saml_immutable_id != null && length(var.pf_saml_immutable_id) == 24)
    error_message = "Set the approved 24-character ImmutableID before staging the MSFT11 mapping."
  }
}

variable "pf_msft11_source_admin_url" {
  description = "HTTPS admin base URL of the approved source PF console containing the MSFT11 generator (no trailing slash)."
  type        = string
  default     = null
  validation {
    condition     = var.pf_msft11_source_admin_url == null ? !var.stage_msft11_generator : startswith(var.pf_msft11_source_admin_url, "https://") && !endswith(var.pf_msft11_source_admin_url, "/")
    error_message = "Set pf_msft11_source_admin_url to the approved HTTPS admin URL before staging the generator."
  }
}

variable "pf_saml_expected_subject" {
  description = "Exact authenticated portal subject allowed by the staged one-user SAML exchange policy; never use this for email-based account lookup."
  type        = string
  default     = null
  validation {
    condition     = var.pf_saml_expected_subject == null ? !var.create_saml_processor_policy : length(trimspace(var.pf_saml_expected_subject)) > 0
    error_message = "Set pf_saml_expected_subject when staging the SAML processor policy."
  }
}

variable "entra_app_display_name" {
  description = "Display name of the single-tenant Entra connector application."
  type        = string
  default     = "PingFederate directory broker connector"
}

variable "activate_clients" {
  description = "Enable the PF OAuth clients only after global scopes, canonical identity mapping, and live introspection are ready for testing."
  type        = bool
  default     = false
}

variable "enable_dev_login" {
  description = "Opt in to one localhost-only Simple PCV/HTML Form user for testing the portal OAuth sign-in. Never use in production."
  type        = bool
  default     = false
}

variable "pf_dev_login_password" {
  description = "Password for the fixed broker-dev-user test account. Supply privately via TF_VAR_pf_dev_login_password; it is still stored in Terraform state."
  type        = string
  default     = null
  sensitive   = true
}

variable "enable_dev_second_login" {
  description = "Opt in to the additional nirving@ping.darkedges.com account in the localhost-only dev credential validator. This does not enable a second Reference ID or SAML connection mapping."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_dev_second_login || var.enable_dev_login
    error_message = "The second dev login requires enable_dev_login=true."
  }
}

variable "pf_dev_second_login_password" {
  description = "Password for the additional localhost-only dev account. Supply privately via TF_VAR_pf_dev_second_login_password; it is stored in Terraform state."
  type        = string
  default     = null
  sensitive   = true
}

variable "enable_local_pf_tls" {
  description = "Opt in to importing the ignored certs/pingfederate-local.p12 bundle as a PF SSL server key. Key material enters Terraform state."
  type        = bool
  default     = false
}

variable "pf_local_tls_keystore_password" {
  description = "Password for the locally generated PF PKCS#12 bundle. Supply through TF_VAR_pf_local_tls_keystore_password; it enters Terraform state."
  type        = string
  default     = null
  sensitive   = true
}

variable "activate_local_pf_tls" {
  description = "After the SSL key import succeeds, adopt PF's existing SSL settings and make that key the localhost admin and runtime default. Review the singleton plan first."
  type        = bool
  default     = false
  validation {
    condition     = !var.activate_local_pf_tls || var.enable_local_pf_tls
    error_message = "Enable the local PF TLS key import before activating it."
  }
}

variable "attach_pf_token_contract" {
  description = "Second-stage apply: attach the now-created token managers and OIDC policy to the disabled PF clients. Keep false for the first apply."
  type        = bool
  default     = false
}

variable "pf_handoff" {
  description = <<-EOT
    Set after installing the Agentless Integration Kit and inspecting its
    Reference ID SP Adapter descriptor. The four fulfillment mappings must
    come from validated PF identity and token-response context, never browser
    input. A null value leaves the handoff resources uncreated.
  EOT
  type = object({
    reference_adapter_plugin_id = string
    adapter_fields = list(object({
      name  = string
      value = string
    }))
    adapter_sensitive_fields = list(object({
      name  = string
      value = string
    }))
    attribute_fulfillment = map(object({
      source = object({
        type = string
        id   = optional(string)
      })
      value = optional(string)
    }))
    idp_identity_mapping = string
  })
  default   = null
  sensitive = true
  validation {
    condition = var.pf_handoff == null ? true : (
      length(setsubtract(toset(["subject", "entra_tid", "entra_oid", "entra_token_response"]), toset(keys(var.pf_handoff.attribute_fulfillment)))) == 0 &&
      contains(["ACCOUNT_LINKING", "ACCOUNT_MAPPING", "NONE"], var.pf_handoff.idp_identity_mapping)
    )
    error_message = "The handoff needs all four broker attributes and a supported PF identity mapping."
  }
  validation {
    condition = var.pf_handoff == null ? true : (
      try(var.pf_handoff.attribute_fulfillment["entra_token_response"].source.type == "CONTEXT", false) &&
      alltrue([for name in ["subject", "entra_tid", "entra_oid"] :
        !contains(["REQUEST", "TRACKED_HTTP_PARAMS", "TEXT"], try(var.pf_handoff.attribute_fulfillment[name].source.type, "REQUEST"))
      ])
    )
    error_message = "Map the token response from PF context, and identity attributes from validated non-request sources."
  }
}

variable "enable_dev_handoff" {
  description = "Opt in to the localhost-only Agentless Reference ID handoff. It links one validated Entra tenant/object ID to the single broker-dev-user login; never enable on a shared or production PF instance."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_dev_handoff || (var.enable_dev_login && var.pf_handoff == null)
    error_message = "The dev handoff requires enable_dev_login=true and cannot be combined with pf_handoff."
  }
}

variable "enable_dev_handoff_probe" {
  description = "Diagnostic only: in the localhost dev handoff, send a harmless marker instead of the Entra token response through the Reference ID adapter. The broker will reject it; turn this off after one test."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_dev_handoff_probe || var.enable_dev_handoff
    error_message = "The handoff probe requires enable_dev_handoff=true."
  }
}

variable "pf_dev_link_entra_oid" {
  description = "Immutable Entra object ID of the only account allowed to link as broker-dev-user in the localhost demo."
  type        = string
  default     = null
  validation {
    condition     = var.pf_dev_link_entra_oid == null || can(regex("^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", var.pf_dev_link_entra_oid))
    error_message = "Enter an Entra object GUID for pf_dev_link_entra_oid."
  }
}

variable "pf_dev_reference_adapter_plugin_id" {
  description = "SP Reference ID adapter descriptor ID for the installed Agentless kit; defaults to the class found in the local 2.3.1 JAR. Override if the PF admin API reports a different ID."
  type        = string
  default     = "com.pingidentity.pf.adapters.referenceid.SpBackchannelReferenceAuthnAdapter"
}

variable "pf_dev_pickup_username" {
  description = "HTTP Basic username for the localhost Reference ID pickup, matching PF_PICKUP_USER in the broker environment."
  type        = string
  default     = "directory-broker-pickup"
}

variable "pf_dev_pickup_password" {
  description = "HTTP Basic password for the localhost Reference ID pickup, matching PF_PICKUP_PASSWORD in the broker environment. Supply through TF_VAR_pf_dev_pickup_password."
  type        = string
  default     = null
  sensitive   = true
}
