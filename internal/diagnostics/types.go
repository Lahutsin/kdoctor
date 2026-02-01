package diagnostics

// Issue captures a single detected problem in the cluster.
type Issue struct {
	Kind           string   // Kubernetes kind, e.g. Pod or Node
	Namespace      string   // Namespace if applicable
	Name           string   // Object name
	Severity       Severity // info | warning | critical
	Summary        string   // Short description of the issue
	Recommendation string   // Actionable suggestion
	References     []string // Optional links to docs or commands
}

// Severity is a lightweight label to sort issues.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)
