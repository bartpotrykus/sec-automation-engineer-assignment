# Terraform — VulnTracker API (Kubernetes / AKS)

Deploys the Python API to a Kubernetes cluster with the security controls the
assignment requires. This is a deployment definition; applying it needs a
cluster with the **Secrets Store CSI driver** + **Azure Key Vault provider** and
**workload identity** enabled (standard AKS add-ons).

## Security controls

| Requirement | How |
| ----------- | --- |
| Secrets from a secrets manager | `SecretProviderClass` pulls `SECRET_KEY` / `DATABASE_URL` from **Azure Key Vault** via the CSI driver using a **workload identity**. No secret values in this repo, the manifests, or Terraform state. |
| Restrict ingress | `NetworkPolicy` default-denies, then allows ingress **only** from the ingress-controller namespace on port 8000; egress limited to DNS + 443. `Service` is `ClusterIP` (no direct external exposure). |
| Resource limits | CPU/memory `requests` and `limits` on the container. |
| Security context | Pod & container: `runAsNonRoot` (uid 10001), `readOnlyRootFilesystem`, `allowPrivilegeEscalation=false`, all capabilities dropped, `seccompProfile=RuntimeDefault`, SA token automount disabled. Writable `emptyDir`s for `/data` and `/tmp`. |

## Usage

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in your values (no secrets)
terraform init
terraform plan
terraform apply
```

Prerequisites in Key Vault: secrets named `SECRET-KEY` and `DATABASE-URL`
(e.g. a managed Postgres connection string for production rather than SQLite).

## Scanning

Static IaC scan (see [../reports/iac.trivy.json](../reports/iac.trivy.json)):

```bash
trivy config terraform/ --format json --output reports/iac.trivy.json
```
