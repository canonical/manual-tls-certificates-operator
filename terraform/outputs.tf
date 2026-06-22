# Copyright 2024-2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "application" {
  description = "The deployed `juju_application` resource"
  value       = juju_application.manual_tls_certificates
}

output "provides" {
  description = "Map of provides endpoint names"
  value = {
    certificates      = "certificates"
    trust_certificate = "trust_certificate"
  }
}

output "requires" {
  description = "Map of requires endpoint names"
  value = {
    tracing = "tracing"
  }
}
