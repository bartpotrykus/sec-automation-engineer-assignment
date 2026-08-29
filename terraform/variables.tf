variable "kubeconfig_path" {
  description = "Path to the kubeconfig for the target cluster (e.g. AKS)."
  type        = string
  default     = "~/.kube/config"
}

variable "namespace" {
  description = "Namespace to deploy VulnTracker into."
  type        = string
  default     = "vulntracker"
}

variable "image" {
  description = "Fully qualified, digest-pinned image reference (registry/vulntracker-api@sha256:...)."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be digest-pinned, e.g. registry/vulntracker-api@sha256:<64 hex chars>."
  }
}

variable "replicas" {
  description = "Number of API replicas."
  type        = number
  default     = 2
}

# --- Secrets: sourced from Azure Key Vault via the Secrets Store CSI driver ---
# No secret VALUES are declared here — only references. The CSI driver reads
# them from Key Vault at runtime using a workload identity.

variable "key_vault_name" {
  description = "Azure Key Vault name that holds SECRET_KEY and DATABASE_URL."
  type        = string
}

variable "azure_tenant_id" {
  description = "Azure AD tenant ID for the Key Vault."
  type        = string
}

variable "workload_identity_client_id" {
  description = "Client ID of the workload identity the CSI driver uses to read Key Vault."
  type        = string
}

variable "ingress_namespace" {
  description = "Namespace of the ingress controller permitted to reach the service."
  type        = string
  default     = "ingress-nginx"
}

variable "resources" {
  description = "Container resource requests/limits."
  type = object({
    requests = object({ cpu = string, memory = string })
    limits   = object({ cpu = string, memory = string })
  })
  default = {
    requests = { cpu = "100m", memory = "128Mi" }
    limits   = { cpu = "500m", memory = "256Mi" }
  }
}
