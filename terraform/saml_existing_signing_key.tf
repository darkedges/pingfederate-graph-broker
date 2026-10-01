# Imported through the PingFederate Admin API without putting the remote
# private signing key, encrypted PKCS#12 bytes, or export password in state.
# Treat this as a read-only dependency; changing the expected fingerprint
# must be an explicit review of the federation signing-key rollover.
data "pingfederate_keypairs_signing_key" "msft11_local" {
  key_id = "broker-msft11-import"

  lifecycle {
    postcondition {
      condition     = self.sha256_fingerprint == "A512AA0F3CEB5D1C091200679722C154FA010FF54F8AB1686DEA25536A3229A6"
      error_message = "The imported local MSFT11 signing certificate does not match the reviewed remote certificate."
    }
  }
}
