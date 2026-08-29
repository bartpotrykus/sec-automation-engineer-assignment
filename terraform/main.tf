locals {
  app_labels = {
    app                          = "vulntracker-api"
    "app.kubernetes.io/name"     = "vulntracker-api"
    "app.kubernetes.io/part-of"  = "vulntracker"
  }
}

resource "kubernetes_namespace_v1" "this" {
  metadata {
    name = var.namespace
    labels = {
      "kubernetes.io/metadata.name" = var.namespace
    }
  }
}

# Workload identity used by the CSI driver to read Key Vault (no static creds).
resource "kubernetes_service_account_v1" "api" {
  metadata {
    name      = "vulntracker-api"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    annotations = {
      "azure.workload.identity/client-id" = var.workload_identity_client_id
    }
    labels = local.app_labels
  }
  automount_service_account_token = false
}

# Secrets come from Azure Key Vault via the Secrets Store CSI driver and are
# synced into a Kubernetes Secret consumed by the container as env vars.
# Nothing secret is stored in this repo, in the manifest, or in Terraform state.
resource "kubernetes_manifest" "secret_provider_class" {
  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "vulntracker-kv"
      namespace = kubernetes_namespace_v1.this.metadata[0].name
    }
    spec = {
      provider = "azure"
      parameters = {
        usePodIdentity         = "false"
        useWorkloadIdentity    = "true"
        keyvaultName           = var.key_vault_name
        tenantId               = var.azure_tenant_id
        objects = yamlencode({
          array = [
            { objectName = "SECRET-KEY", objectType = "secret" },
            { objectName = "DATABASE-URL", objectType = "secret" },
          ]
        })
      }
      # Sync the mounted secrets into a K8s Secret for env consumption.
      secretObjects = [{
        secretName = "vulntracker-secrets"
        type       = "Opaque"
        data = [
          { objectName = "SECRET-KEY", key = "SECRET_KEY" },
          { objectName = "DATABASE-URL", key = "DATABASE_URL" },
        ]
      }]
    }
  }
}

resource "kubernetes_deployment_v1" "api" {
  # checkov:skip=CKV_K8S_14:Image is digest-pinned — enforced by the var.image validation (@sha256:)
  # checkov:skip=CKV_K8S_43:Image is digest-pinned — enforced by the var.image validation (@sha256:)
  # checkov:skip=CKV_K8S_35:Secrets come from Azure Key Vault via the CSI driver (never hardcoded) and are injected as env for app compatibility; file-based consumption is tracked as future hardening
  metadata {
    name      = "vulntracker-api"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.app_labels
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = { app = local.app_labels.app }
    }

    template {
      metadata {
        labels = merge(local.app_labels, { "azure.workload.identity/use" = "true" })
      }

      spec {
        service_account_name             = kubernetes_service_account_v1.api.metadata[0].name
        automount_service_account_token  = false

        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001
          fs_group        = 10001
          seccomp_profile { type = "RuntimeDefault" }
        }

        container {
          name              = "api"
          image             = var.image
          image_pull_policy = "Always"

          port {
            container_port = 8000
            protocol       = "TCP"
          }

          # Secrets injected from the CSI-synced Kubernetes Secret.
          env {
            name = "SECRET_KEY"
            value_from {
              secret_key_ref {
                name = "vulntracker-secrets"
                key  = "SECRET_KEY"
              }
            }
          }
          env {
            name = "DATABASE_URL"
            value_from {
              secret_key_ref {
                name = "vulntracker-secrets"
                key  = "DATABASE_URL"
              }
            }
          }

          security_context {
            allow_privilege_escalation = false
            privileged                 = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 10001
            capabilities { drop = ["ALL"] }
          }

          resources {
            requests = var.resources.requests
            limits   = var.resources.limits
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 10
            period_seconds        = 30
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 5
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          # Writable, ephemeral mounts so the root filesystem can stay read-only.
          volume_mount {
            name       = "data"
            mount_path = "/data"
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          volume_mount {
            name       = "secrets-store"
            mount_path = "/mnt/secrets-store"
            read_only  = true
          }
        }

        volume {
          name = "data"
          empty_dir {}
        }
        volume {
          name = "tmp"
          empty_dir {}
        }
        volume {
          name = "secrets-store"
          csi {
            driver    = "secrets-store.csi.k8s.io"
            read_only = true
            volume_attributes = {
              # checkov:skip=CKV_SECRET_6:False positive — this is the SecretProviderClass resource name, not a secret value
              secretProviderClass = "vulntracker-kv"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "api" {
  metadata {
    name      = "vulntracker-api"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.app_labels
  }
  spec {
    type     = "ClusterIP" # not exposed directly; reached only via the ingress controller
    selector = { app = local.app_labels.app }
    port {
      port        = 80
      target_port = 8000
      protocol    = "TCP"
    }
  }
}

# Default-deny with narrow allowances: ingress only from the ingress controller
# on 8000; egress only DNS + HTTPS (Key Vault / notify).
resource "kubernetes_network_policy_v1" "api" {
  metadata {
    name      = "vulntracker-api"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  spec {
    pod_selector {
      match_labels = { app = local.app_labels.app }
    }
    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = { "kubernetes.io/metadata.name" = var.ingress_namespace }
        }
      }
      ports {
        port     = "8000"
        protocol = "TCP"
      }
    }

    egress {
      # DNS resolution
      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
        protocol = "TCP"
      }
    }
    egress {
      # HTTPS egress (Key Vault, downstream APIs)
      ports {
        port     = "443"
        protocol = "TCP"
      }
    }
  }
}
