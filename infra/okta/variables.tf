variable "org_name" {
  description = "Okta org subdomain, e.g. 'dev-12345678' for dev-12345678.okta.com"
  type        = string
}

variable "base_url" {
  description = "Okta base URL: 'okta.com' for production orgs, 'oktapreview.com' for preview"
  type        = string
  default     = "okta.com"
}

variable "api_token" {
  description = <<-EOT
    Okta API token with admin rights.

    Prefer the OKTA_API_TOKEN environment variable over a tfvars file — a token
    committed to source control is a real incident, unlike a client_id
    (README §E.5).
  EOT
  type      = string
  sensitive = true
}

variable "apia_jwks_uri" {
  description = <<-EOT
    HTTPS URL serving ApiA's PUBLIC signing key as a JWK Set.

    If you cannot host one, omit it and paste the public JWK into the app
    integration by hand instead (README §6.6). The PRIVATE key must never leave
    the server that generated it.
  EOT
  type    = string
  default = null
}

variable "apib_jwks_uri" {
  description = "HTTPS URL serving ApiB's PUBLIC signing key as a JWK Set. See apia_jwks_uri."
  type        = string
  default     = null
}
