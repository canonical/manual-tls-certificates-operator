# Copyright 2024-2026 Canonical Ltd.
# See LICENSE file for licensing details.


output "app_name" {
  description = "Application name"
  value       = juju_application.manual_tls_certificates.name
}

output "provides" {
  description = "Map of provides endpoints"
  value = {
    certificates      = "certificates"
    trust_certificate = "trust_certificate"
  }
}

output "requires" {
  description = "Map of requires endpoints"
  value = {
    tracing = "tracing"
  }
}

output "offers" {
  description = "Map of Juju offer URLs"
  value = {
    certificates      = juju_offer.certificates.url
    trust_certificate = juju_offer.trust_certificate.url
  }
}
