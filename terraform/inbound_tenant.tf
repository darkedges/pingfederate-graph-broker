variable "inbound_entra_tenant_id" {
  type        = string
  default     = null
  description = "Separate Entra tenant for inbound token exchange; null preserves the broker tenant."
  validation {
    condition     = var.inbound_entra_tenant_id == null || can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.inbound_entra_tenant_id))
    error_message = "Provide an Entra tenant UUID."
  }
}

locals {
  inbound_tenant_id = coalesce(var.inbound_entra_tenant_id, var.entra_tenant_id)
}
