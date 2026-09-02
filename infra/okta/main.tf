###############################################################################
# Okta tenant configuration for the SSO reference architecture.
#
# Creates everything README §6 describes, in the Variant B topology
# (one Custom Authorization Server per API — README §5.2).
#
#   terraform init
#   terraform plan  -var-file=terraform.tfvars
#   terraform apply -var-file=terraform.tfvars
#
# Then run ./export-appsettings.ps1 to emit the values into the four
# appsettings files (README Appendix B).
#
# NOT covered here, because provider support varies by version — do these in
# the Admin Console and record them in your runbook:
#   * Trusted servers (README §5.7) — required for On-Behalf-Of token exchange.
#     Security → API → apib-as → Trusted Servers → add apia-as, and vice versa.
#   * The Token Exchange grant on the two service apps.
#   * Global Session Policy → "Persist session cookie across browser restarts"
#     (README §10.1) — the single setting that decides whether desktop SSO works.
###############################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.9"
    }
  }
}

provider "okta" {
  org_name  = var.org_name
  base_url  = var.base_url
  api_token = var.api_token
}

###############################################################################
# Groups — identity lives in Okta, permissions live in each application.
# The "App-" prefix is what the groups claim filters on (README §5.5).
###############################################################################

resource "okta_group" "finance" {
  name        = "App-Finance"
  description = "Finance users. Grants invoice access in ApiB."
}

resource "okta_group" "warehouse" {
  name        = "App-Warehouse"
  description = "Warehouse users. Grants order access in ApiA."
}

###############################################################################
# Authorization servers — one per API (README §5.2 Variant B).
#
# Separate servers give independent policies, lifetimes and blast radius, and
# avoid depending on the multi-audience Early Access feature.
###############################################################################

resource "okta_auth_server" "apia" {
  name        = "ApiA Authorization Server"
  description = "Issues access tokens for ApiA"
  audiences   = ["api://apia"]
}

resource "okta_auth_server" "apib" {
  name        = "ApiB Authorization Server"
  description = "Issues access tokens for ApiB"
  audiences   = ["api://apib"]
}

###############################################################################
# Scopes — what class of operation a token permits (README §5.4).
#
# Note there is deliberately no "*.admin" or "full_access" scope: it becomes the
# universal default within a year and you lose the ability to reason about
# blast radius.
###############################################################################

locals {
  apia_scopes = {
    "apia.read"  = "Read ApiA data"
    "apia.write" = "Modify ApiA data"
  }

  apib_scopes = {
    "apib.read"  = "Read ApiB data"
    "apib.write" = "Modify ApiB data"
  }
}

resource "okta_auth_server_scope" "apia" {
  for_each = local.apia_scopes

  auth_server_id   = okta_auth_server.apia.id
  name             = each.key
  display_name     = each.value
  description      = each.value
  consent          = "IMPLICIT" # first-party apps; wrong for a third-party integration
  metadata_publish = "ALL_CLIENTS"
}

resource "okta_auth_server_scope" "apib" {
  for_each = local.apib_scopes

  auth_server_id   = okta_auth_server.apib.id
  name             = each.key
  display_name     = each.value
  description      = each.value
  consent          = "IMPLICIT"
  metadata_publish = "ALL_CLIENTS"
}

###############################################################################
# Groups claim — FILTERED. Without the filter you emit every group the user
# belongs to, which bloats the token past IIS/proxy header limits and leaks the
# org chart to every resource server (README §5.5, §13.6).
###############################################################################

resource "okta_auth_server_claim" "apia_groups" {
  auth_server_id    = okta_auth_server.apia.id
  name              = "groups"
  claim_type        = "RESOURCE" # access token
  value_type        = "GROUPS"
  group_filter_type = "STARTS_WITH"
  value             = "App-"
  always_include_in_token = true
}

resource "okta_auth_server_claim" "apib_groups" {
  auth_server_id    = okta_auth_server.apib.id
  name              = "groups"
  claim_type        = "RESOURCE"
  value_type        = "GROUPS"
  group_filter_type = "STARTS_WITH"
  value             = "App-"
  always_include_in_token = true
}

###############################################################################
# Desktop clients — Native Application, no secret, PKCE enforced (README §4.1).
#
# Every loopback port the client might bind must be registered, or Okta rejects
# the authorize request. Three ports removes the "port already in use" ticket
# without creating an unmanageable allowlist (README §4.3, §8.5).
###############################################################################

resource "okta_app_oauth" "appa" {
  label          = "AppA — WPF Client"
  type           = "native"
  grant_types    = ["authorization_code", "refresh_token"]
  response_types = ["code"]

  token_endpoint_auth_method = "none" # public client; PKCE is enforced
  pkce_required              = true

  redirect_uris = [
    "http://127.0.0.1:8765/callback",
    "http://127.0.0.1:8766/callback",
    "http://127.0.0.1:8767/callback",
  ]

  post_logout_redirect_uris = [
    "http://127.0.0.1:8765/signout-callback",
    "http://127.0.0.1:8766/signout-callback",
    "http://127.0.0.1:8767/signout-callback",
  ]

  # Rotating refresh tokens: reuse of a rotated token is proof of theft (README §5.6).
  refresh_token_rotation = "ROTATE"
  refresh_token_leeway   = 30 # seconds of grace for a racing retry — never set 0
}

resource "okta_app_oauth" "appb" {
  label          = "AppB — WPF Client"
  type           = "native"
  grant_types    = ["authorization_code", "refresh_token"]
  response_types = ["code"]

  token_endpoint_auth_method = "none"
  pkce_required              = true

  redirect_uris = [
    "http://127.0.0.1:8865/callback",
    "http://127.0.0.1:8866/callback",
    "http://127.0.0.1:8867/callback",
  ]

  post_logout_redirect_uris = [
    "http://127.0.0.1:8865/signout-callback",
    "http://127.0.0.1:8866/signout-callback",
    "http://127.0.0.1:8867/signout-callback",
  ]

  refresh_token_rotation = "ROTATE"
  refresh_token_leeway   = 30
}

###############################################################################
# Service identities — each API as a CLIENT when it calls the other.
#
# These are distinct from the APIs as RESOURCES (the audiences above). ApiA
# appears twice in the design for exactly this reason (README §5.3).
#
# private_key_jwt, not a shared secret: the private key is generated on the
# server, marked non-exportable, and never transported (README §4.4, §6.6).
###############################################################################

resource "okta_app_oauth" "apia_service" {
  label       = "ApiA — Service Identity"
  type        = "service"
  grant_types = ["client_credentials"]

  token_endpoint_auth_method = "private_key_jwt"
  jwks_uri                   = var.apia_jwks_uri

  lifecycle {
    # The Token Exchange grant and the JWKS may be managed outside Terraform
    # depending on provider version — do not fight over them on every apply.
    ignore_changes = [grant_types]
  }
}

resource "okta_app_oauth" "apib_service" {
  label       = "ApiB — Service Identity"
  type        = "service"
  grant_types = ["client_credentials"]

  token_endpoint_auth_method = "private_key_jwt"
  jwks_uri                   = var.apib_jwks_uri

  lifecycle {
    ignore_changes = [grant_types]
  }
}

###############################################################################
# Assignments — a SEPARATE gate from access policy. A user who satisfies your
# policy but is not assigned gets access_denied, with an identical error
# (README §3.5). Always check both when debugging.
###############################################################################

resource "okta_app_group_assignment" "appa_finance" {
  app_id   = okta_app_oauth.appa.id
  group_id = okta_group.finance.id
}

resource "okta_app_group_assignment" "appa_warehouse" {
  app_id   = okta_app_oauth.appa.id
  group_id = okta_group.warehouse.id
}

resource "okta_app_group_assignment" "appb_finance" {
  app_id   = okta_app_oauth.appb.id
  group_id = okta_group.finance.id
}

###############################################################################
# Access policies — which client gets which scopes, and for how long.
#
# Access token lifetime is 15 minutes because a JWT cannot be revoked mid-life:
# the lifetime IS your revocation window (README §5.6, §11.4).
###############################################################################

resource "okta_auth_server_policy" "apia_clients" {
  auth_server_id   = okta_auth_server.apia.id
  name             = "ApiA clients"
  description      = "Token issuance for clients of ApiA"
  priority         = 1
  client_whitelist = [okta_app_oauth.appa.id, okta_app_oauth.apib_service.id]
}

resource "okta_auth_server_policy_rule" "apia_appa" {
  auth_server_id       = okta_auth_server.apia.id
  policy_id            = okta_auth_server_policy.apia_clients.id
  name                 = "AppA — authorization code"
  priority             = 1
  grant_type_whitelist = ["authorization_code"]
  scope_whitelist      = ["openid", "profile", "email", "offline_access", "apia.read", "apia.write"]
  group_whitelist      = ["EVERYONE"]

  access_token_lifetime_minutes             = 15
  refresh_token_lifetime_minutes            = 129600 # 90 days
  refresh_token_window_minutes              = 10080  # 7-day idle window
}

resource "okta_auth_server_policy_rule" "apia_service_to_service" {
  auth_server_id       = okta_auth_server.apia.id
  policy_id            = okta_auth_server_policy.apia_clients.id
  name                 = "ApiB service — client credentials"
  priority             = 2
  grant_type_whitelist = ["client_credentials"]
  scope_whitelist      = ["apia.read"]
  group_whitelist      = ["EVERYONE"]

  access_token_lifetime_minutes = 15
}

resource "okta_auth_server_policy" "apib_clients" {
  auth_server_id   = okta_auth_server.apib.id
  name             = "ApiB clients"
  description      = "Token issuance for clients of ApiB"
  priority         = 1
  client_whitelist = [okta_app_oauth.appb.id, okta_app_oauth.apia_service.id]
}

resource "okta_auth_server_policy_rule" "apib_appb" {
  auth_server_id       = okta_auth_server.apib.id
  policy_id            = okta_auth_server_policy.apib_clients.id
  name                 = "AppB — authorization code"
  priority             = 1
  grant_type_whitelist = ["authorization_code"]
  scope_whitelist      = ["openid", "profile", "email", "offline_access", "apib.read", "apib.write"]
  group_whitelist      = ["EVERYONE"]

  access_token_lifetime_minutes  = 15
  refresh_token_lifetime_minutes = 129600
  refresh_token_window_minutes   = 10080
}

resource "okta_auth_server_policy_rule" "apib_service_to_service" {
  auth_server_id       = okta_auth_server.apib.id
  policy_id            = okta_auth_server_policy.apib_clients.id
  name                 = "ApiA service — client credentials"
  priority             = 2
  grant_type_whitelist = ["client_credentials"]
  scope_whitelist      = ["apib.read"]
  group_whitelist      = ["EVERYONE"]

  access_token_lifetime_minutes = 15
}
