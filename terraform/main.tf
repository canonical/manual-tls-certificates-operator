# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

/**
 * # Terraform module for the manual-tls-certificates charm
 *
 * This is a Terraform module facilitating the deployment of the manual-tls-certificates
 * charm using the Juju Terraform provider.
 */

resource "juju_application" "manual_tls_certificates" {
  name        = var.app_name
  model_uuid  = var.model_uuid
  config      = var.config
  constraints = var.constraints
  units       = var.units

  charm {
    name     = "manual-tls-certificates"
    base     = var.base
    channel  = var.channel
    revision = var.revision
  }
}

