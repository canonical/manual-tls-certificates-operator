# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Name of the application"
  type        = string
  default     = "manual-tls-certificates"
}

variable "base" {
  description = "Operating system (for example, ubuntu@22.04)"
  type        = string
  default     = "ubuntu@24.04"
}

variable "channel" {
  description = "Charm channel to deploy from"
  type        = string
  default     = "1/stable"
}

variable "config" {
  description = "Map of charm configuration options"
  type        = map(string)
  default     = {}
}

variable "constraints" {
  description = "Constraints string"
  type        = string
  default     = null
}

variable "model_uuid" {
  description = "UUID of the Juju model to deploy the charm into"
  type        = string
}

variable "revision" {
  description = "Charm revision to deploy. Null deploys the latest on given channel"
  type        = number
  default     = null
}

variable "units" {
  description = "Number of application units to deploy"
  type        = number
  default     = 1
}
