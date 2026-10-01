# Development-only OAuth login. This deliberately creates one isolated
# credential validator, HTML Form IdP adapter and persistent-grant mapping.
# Do not enable outside a localhost PF runtime/admin API. The password remains in state.
resource "pingfederate_password_credential_validator" "dev_login" {
  count        = var.enable_dev_login ? 1 : 0
  validator_id = "brokerDevPCV"
  name         = "Directory broker DEV-ONLY local user"

  plugin_descriptor_ref = {
    id = "org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"
  }
  attribute_contract = {}
  configuration = {
    tables = [{
      name = "Users"
      rows = concat([{
        default_row = false
        fields = [
          { name = "Username", value = "broker-dev-user" },
          { name = "Relax Password Requirements", value = "false" },
        ]
        sensitive_fields = [
          { name = "Password", value = var.pf_dev_login_password },
          { name = "Confirm Password", value = var.pf_dev_login_password },
        ]
        }], var.enable_dev_second_login ? [{
        default_row = false
        fields = [
          { name = "Username", value = "nirving@ping.darkedges.com" },
          { name = "Relax Password Requirements", value = "false" },
        ]
        sensitive_fields = [
          { name = "Password", value = var.pf_dev_second_login_password },
          { name = "Confirm Password", value = var.pf_dev_second_login_password },
        ]
      }] : [])
    }]
  }

  lifecycle {
    precondition {
      condition     = can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_public_url))
      error_message = "The dev-only login may be enabled only for a localhost PF runtime."
    }
    precondition {
      condition     = can(regex("^https://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$", var.pf_admin_url))
      error_message = "The dev-only login may be enabled only through a localhost PF admin API."
    }
    precondition {
      condition     = nonsensitive(try(length(var.pf_dev_login_password) >= 8, false))
      error_message = "Supply a dev login password of at least 8 characters using TF_VAR_pf_dev_login_password."
    }
    precondition {
      condition     = !var.enable_dev_second_login || nonsensitive(try(length(var.pf_dev_second_login_password) >= 8, false))
      error_message = "Supply a second dev login password of at least 8 characters using TF_VAR_pf_dev_second_login_password."
    }
  }
}

resource "pingfederate_idp_adapter" "dev_login" {
  count      = var.enable_dev_login ? 1 : 0
  adapter_id = "brokerDevHTMLForm"
  name       = "Directory broker DEV-ONLY HTML Form"

  plugin_descriptor_ref = {
    id = "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"
  }
  configuration = {
    fields = [
      { name = "Challenge Retries", value = "3" },
      { name = "Session State", value = "None" },
      { name = "Login Template", value = "html.form.login.template.html" },
      { name = "Allow Password Changes", value = "false" },
      { name = "Enable 'Remember My Username'", value = "false" },
    ]
    tables = [{
      name = "Credential Validators"
      rows = [{
        default_row = false
        fields = [{
          name  = "Password Credential Validator Instance"
          value = pingfederate_password_credential_validator.dev_login[0].id
        }]
      }]
    }]
  }
  attribute_contract = {
    core_attributes = [
      { name = "policy.action", pseudonym = false, masked = false },
      { name = "username", pseudonym = true, masked = false },
    ]
    unique_user_key_attribute = "username"
  }
  attribute_mapping = {
    attribute_contract_fulfillment = {
      "policy.action" = { source = { type = "ADAPTER" }, value = "policy.action" }
      username        = { source = { type = "ADAPTER" }, value = "username" }
    }
  }
}

# The username is a fixed dev-only identifier, never an email or request
# parameter. The user token's sub is subsequently mapped from USER_KEY.
resource "pingfederate_oauth_idp_adapter_mapping" "dev_login" {
  count      = var.enable_dev_login ? 1 : 0
  mapping_id = pingfederate_idp_adapter.dev_login[0].id
  attribute_contract_fulfillment = {
    USER_KEY  = { source = { type = "ADAPTER" }, value = "username" }
    USER_NAME = { source = { type = "ADAPTER" }, value = "username" }
  }
}
