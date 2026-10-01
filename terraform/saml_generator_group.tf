# PF provider 1.9.0 exposes the singleton default-group settings but not the
# generator-group object itself. Stage both through the local Admin API, and
# refuse to overwrite an unrelated default group. This is a localhost-only
# singleton; disabling the flag does not delete the group or clear the default.
resource "terraform_data" "msft11_generator_group_stage" {
  count = var.stage_msft11_generator_group ? 1 : 0

  triggers_replace = [
    var.pf_admin_url,
    filesha256("${path.module}/scripts/stage_msft11_generator_group.ps1"),
    data.pingfederate_keypairs_signing_key.msft11_local.sha256_fingerprint,
  ]

  depends_on = [pingfederate_oauth_token_exchange_token_generator_mapping.broker_user_msft11]

  provisioner "local-exec" {
    command     = "pwsh -NoProfile -File ./scripts/stage_msft11_generator_group.ps1"
    working_dir = path.module
    environment = {
      PF_LOCAL_ADMIN_URL = var.pf_admin_url
    }
  }
}
