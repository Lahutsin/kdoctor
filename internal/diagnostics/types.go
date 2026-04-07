package diagnostics

import "fmt"

// Issue captures a single detected problem in the cluster.
type Issue struct {
	Kind           string   `json:"kind"`
	Namespace      string   `json:"namespace,omitempty"`
	Name           string   `json:"name,omitempty"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category,omitempty"`
	Check          string   `json:"check,omitempty"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references,omitempty"`
}

// Severity is a lightweight label to sort issues.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func (i Issue) Key() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", i.Kind, i.Namespace, i.Name, i.Check, i.Summary)
}

func (i Issue) EffectiveCategory() string {
	if i.Category != "" {
		return i.Category
	}
	return CategoryForKind(i.Kind)
}

func CategoryForKind(kind string) string {
	switch kind {
	case "Pod", "Deployment", "DaemonSet", "ReplicaSet", "Job", "CronJob", "HPA", "PDB":
		return "workloads"
	case "Node", "CNI", "Ingress", "DNS":
		return "networking"
	case "PVC", "PV", "CSI", "StorageClass":
		return "storage"
	case "Webhook", "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "TLSSecret", "Certificate":
		return "security"
	case "APIServer", "etcd", "ControlPlane", "ResourceQuota", "Baseline":
		return "control-plane"
	default:
		return "general"
	}
}
