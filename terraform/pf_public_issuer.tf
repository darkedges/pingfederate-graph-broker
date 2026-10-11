# Virtual issuers leave the global base URL and existing flows intact.
variable "manage_pf_virtual_issuer" {
  type    = bool
  default = false
}
data "pingfederate_virtual_host_names" "existing" {
  count = var.manage_pf_virtual_issuer ? 1 : 0
}
resource "pingfederate_virtual_host_names" "public_issuer" {
  count              = var.manage_pf_virtual_issuer ? 1 : 0
  virtual_host_names = setunion(data.pingfederate_virtual_host_names.existing[0].virtual_host_names, toset([trimprefix(local.inbound_first_issuer, "https://")]))
  lifecycle { prevent_destroy = true }
}
import {
  for_each = var.manage_pf_virtual_issuer ? toset(["public"]) : toset([])
  to       = pingfederate_virtual_host_names.public_issuer[0]
  id       = "virtualHostNames"
}
resource "pingfederate_oauth_issuer" "inbound" {
  count       = var.manage_pf_virtual_issuer ? 1 : 0
  issuer_id   = "brokerEntraPublic"
  name        = "Broker public Entra-first issuer"
  host        = trimprefix(local.inbound_first_issuer, "https://")
  description = "Public issuer for the broker inspector; localhost base URL is unchanged."
  depends_on  = [pingfederate_virtual_host_names.public_issuer]
  lifecycle {
    precondition {
      condition     = can(regex("^https://[A-Za-z0-9.-]+(:[0-9]+)?$", local.inbound_first_issuer))
      error_message = "Use an HTTPS origin without a path or trailing slash for the public virtual issuer."
    }
  }
}
