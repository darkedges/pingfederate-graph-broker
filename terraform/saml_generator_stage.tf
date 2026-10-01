# The reviewed MSFT11 generator uses an OGNL expression for Entra claim
# namespaces. Enabling expressions affects the whole localhost PF instance,
# so this is opt-in together with generator staging and never targets remote PF.
resource "terraform_data" "local_pf_expressions" {
  count = var.stage_msft11_generator ? 1 : 0

  triggers_replace = [
    var.pf_admin_url,
    filesha256("${path.module}/scripts/enable_local_pf_expressions.ps1"),
  ]

  provisioner "local-exec" {
    command     = "pwsh -NoProfile -File ./scripts/enable_local_pf_expressions.ps1"
    working_dir = path.module
    environment = {
      PF_LOCAL_ADMIN_URL = var.pf_admin_url
    }
  }
}

# Provider 1.9.0 has no SP token-generator resource. This local-only bridge
# stages the generator through the PF Admin API and pins the imported signer.
# It is idempotent but cannot detect all out-of-band drift; inspect PF before
# attaching a mapping. No source mapping or token/assertion is exported.
resource "terraform_data" "msft11_generator_stage" {
  count = var.stage_msft11_generator ? 1 : 0

  depends_on = [terraform_data.local_pf_expressions]

  triggers_replace = [
    data.pingfederate_keypairs_signing_key.msft11_local.sha256_fingerprint,
    filesha256("${path.module}/scripts/stage_msft11_generator.ps1"),
    var.pf_msft11_source_admin_url,
  ]

  provisioner "local-exec" {
    command     = "pwsh -NoProfile -File ./scripts/stage_msft11_generator.ps1"
    working_dir = path.module
    environment = {
      PF_MSFT11_SOURCE_ADMIN_URL = var.pf_msft11_source_admin_url
      PF_MSFT11_LOCAL_ADMIN_URL  = var.pf_admin_url
      PF_MSFT11_SIGNING_KEY_ID   = data.pingfederate_keypairs_signing_key.msft11_local.key_id
    }
  }
}
