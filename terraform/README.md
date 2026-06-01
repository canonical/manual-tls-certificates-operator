# Terraform module for manual-tls-certificates

This is a Terraform module facilitating the deployment of the manual-tls-certificates charm using
the [Juju Terraform provider](https://github.com/juju/terraform-provider-juju).
For more information, refer to the
[documentation](https://registry.terraform.io/providers/juju/juju/latest/docs)
for the Juju Terraform provider.

## Requirements

- Terraform >= 1.0
- Juju Terraform provider >= 1.0.0, < 2.0.0
- An existing Juju model

## API

### Inputs

| Name          | Type        | Description                                                        | Default                     | Required |
|---------------|-------------|--------------------------------------------------------------------|-----------------------------|:--------:|
| `app_name`    | string      | Name of the application                                            | `"manual-tls-certificates"` |          |
| `base`        | string      | Operating system (e.g. ubuntu@22.04)                               | `null`                      |          |
| `channel`     | string      | Charm channel to deploy from                                       | `"1/stable"`                |          |
| `config`      | map(string) | Map of charm configuration options                                 | `{}`                        |          |
| `constraints` | string      | Constraints string                                                 | `null`                      |          |
| `model_uuid`  | string      | UUID of the Juju model to deploy the charm into                    |                             |    Y     |
| `revision`    | number      | Charm revision to deploy. Null deploys the latest on given channel | `null`                      |          |
| `units`       | number      | Number of application units to deploy                              | `1`                         |          |

### Outputs

| Name          | Description                              |
|---------------|------------------------------------------|
| `application` | The deployed `juju_application` resource |
| `provides`    | Map of provides endpoint names           |
| `requires`    | Map of requires endpoint names           |

The `provides` output exposes the following endpoint names:

| Key                 | Endpoint name       |
|---------------------|---------------------|
| `certificates`      | `certificates`      |
| `trust_certificate` | `trust_certificate` |

The `requires` output exposes the following endpoint names:

| Key       | Endpoint name |
|-----------|---------------|
| `tracing` | `tracing`     |

## Usage

Ensure that Terraform is aware of the Juju model dependency of the charm module.

```hcl
module "manual-tls-certificates" {
  source     = "git::https://github.com/canonical/manual-tls-certificates-operator//terraform"
  model_uuid = juju_model.my_model.uuid
}
```

To deploy this module with its required dependency, you can run the following
command:

```shell
terraform apply -var="model_uuid=<MODEL_UUID>" -auto-approve
```
