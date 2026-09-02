# These are the values that go into the four appsettings.json files.
# None of them is secret (README §E.3) — they are published in every authorize
# URL, every token, and the discovery document.

output "appa_client_id" { value = okta_app_oauth.appa.client_id }
output "appb_client_id" { value = okta_app_oauth.appb.client_id }

output "apia_service_client_id" { value = okta_app_oauth.apia_service.client_id }
output "apib_service_client_id" { value = okta_app_oauth.apib_service.client_id }

output "apia_auth_server_id" { value = okta_auth_server.apia.id }
output "apib_auth_server_id" { value = okta_auth_server.apib.id }

output "okta_domain" { value = "${var.org_name}.${var.base_url}" }

output "apia_issuer" {
  value = "https://${var.org_name}.${var.base_url}/oauth2/${okta_auth_server.apia.id}"
}

output "apib_issuer" {
  value = "https://${var.org_name}.${var.base_url}/oauth2/${okta_auth_server.apib.id}"
}

output "manual_steps_remaining" {
  description = "Terraform cannot reliably cover these. Do them in the Admin Console."
  value = <<-EOT

    1. TRUSTED SERVERS (required for On-Behalf-Of — README §5.7)
       Security > API > ApiB Authorization Server > Trusted Servers
         > add "ApiA Authorization Server"
       ...and the reverse, only if ApiB genuinely needs to call ApiA.
       Trust is DIRECTIONAL. Configure each direction as a separate decision.

    2. TOKEN EXCHANGE GRANT
       Applications > "ApiA — Service Identity" > General > Grant type
         > Advanced > tick "Token Exchange"
       ...and the same on "ApiB — Service Identity".

    3. GLOBAL SESSION POLICY (README §10.1)
       Security > Global Session Policy
         > enable "Persist session cookie across browser restarts"
       Without this, closing the last browser window kills desktop SSO and
       AppB prompts every day. This is the single most common SSO complaint,
       and nothing in the application code causes or fixes it.

    4. VERIFY WITH TOKEN PREVIEW (README §6.8)
       Security > API > each server > Token Preview
       Do not write or debug code until this returns a clean token: aud is
       api://apia (not the org URL), scp holds exactly what you expect, and
       groups is present and filtered.
  EOT
}
