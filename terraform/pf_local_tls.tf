# PingFederate does not consume the PingData KEYSTORE_FILE container setting.
# Its SSL certificate is a PF product configuration managed through the API.
# This is for the one-machine localhost demo only. The encrypted PKCS#12
# bundle and its password enter Terraform state; protect state and saved plans.
locals {
  pf_local_tls_bundle_path = "${path.module}/../certs/pingfederate-local.p12"
  # Provider schema validates file_data even when count is zero. The
  # precondition below rejects this sentinel whenever import is enabled.
  pf_local_tls_bundle = fileexists(local.pf_local_tls_bundle_path) ? filebase64(local.pf_local_tls_bundle_path) : base64encode("missing-pkcs12-bundle")
}

resource "pingfederate_keypairs_ssl_server_key" "local_mkcert" {
  count = var.enable_local_pf_tls ? 1 : 0

  key_id = "broker-localhost-mkcert"
  # PF rejects mkcert's unencrypted PEM private key. Package the same key and
  # certificate in an encrypted PKCS#12 bundle before applying Terraform.
  file_data = sensitive(local.pf_local_tls_bundle)
  format    = "PKCS12"
  password  = var.pf_local_tls_keystore_password

  lifecycle {
    prevent_destroy = true
    precondition {
      condition = (
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_admin_url)) &&
        can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_public_url))
      )
      error_message = "The local mkcert SSL key may be imported only into a localhost PF admin/runtime instance."
    }
    precondition {
      condition     = fileexists(local.pf_local_tls_bundle_path)
      error_message = "Run scripts/prepare-pf-local-tls.ps1 to create certs/pingfederate-local.p12 before enabling local PF TLS."
    }
    precondition {
      condition     = var.pf_local_tls_keystore_password != null && try(length(var.pf_local_tls_keystore_password) >= 8, false)
      error_message = "Set TF_VAR_pf_local_tls_keystore_password to a private password of at least 8 characters."
    }
  }
}

# This PF-wide singleton must be adopted, not created over an unknown server
# configuration. The conditional import block adopts it before activation.
# The local certificate becomes the sole active default for both 9999 and 9031.
resource "pingfederate_keypairs_ssl_server_settings" "local_mkcert" {
  count = var.activate_local_pf_tls ? 1 : 0

  admin_console_cert_ref = {
    id = pingfederate_keypairs_ssl_server_key.local_mkcert[0].id
  }
  active_admin_console_certs = [{
    id = pingfederate_keypairs_ssl_server_key.local_mkcert[0].id
  }]
  runtime_server_cert_ref = {
    id = pingfederate_keypairs_ssl_server_key.local_mkcert[0].id
  }
  active_runtime_server_certs = [{
    id = pingfederate_keypairs_ssl_server_key.local_mkcert[0].id
  }]

  lifecycle {
    prevent_destroy = true
  }
}

import {
  for_each = var.activate_local_pf_tls ? toset(["existing"]) : toset([])
  to       = pingfederate_keypairs_ssl_server_settings.local_mkcert[0]
  id       = "existing"
}
