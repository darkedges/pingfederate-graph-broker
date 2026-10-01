mock_provider "pingfederate" {
  mock_data "pingfederate_oauth_server_settings" {
    defaults = {
      authorization_code_entropy = 30
      authorization_code_timeout = 60
      refresh_rolling_interval   = 24
      refresh_token_length       = 40
    }
  }
}

override_resource {
  target = pingfederate_oauth_server_settings.broker_scopes
  values = { id = "id" }
}

run "preserve_existing_scopes_and_add_broker_scopes" {
  command = plan

  assert {
    condition = (
      pingfederate_oauth_server_settings.broker_scopes.authorization_code_entropy == 30 &&
      pingfederate_oauth_server_settings.broker_scopes.authorization_code_timeout == 60 &&
      contains([for scope in pingfederate_oauth_server_settings.broker_scopes.scopes : scope.name], "broker.connect") &&
      contains([for scope in pingfederate_oauth_server_settings.broker_scopes.scopes : scope.name], "broker.directory.read")
    )
    error_message = "Scope management must add both broker scopes and retain OAuth timing settings."
  }
}
