package diagnostics

import (
	"fmt"
	"strings"
)

// Issue captures a single detected problem in the cluster.
type Issue struct {
	Kind           string   `json:"kind"`
	Namespace      string   `json:"namespace,omitempty"`
	Name           string   `json:"name,omitempty"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category,omitempty"`
	Check          string   `json:"check,omitempty"`
	Detection      string   `json:"detection,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
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

const (
	DetectionDerived     = "derived"
	DetectionHeuristic   = "heuristic"
	DetectionActiveProbe = "active-probe"
	DetectionPolicy      = "policy"
	DetectionDirect      = "direct"
)

const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

func AllowedDetections() map[string]struct{} {
	return map[string]struct{}{
		DetectionDerived:     {},
		DetectionHeuristic:   {},
		DetectionActiveProbe: {},
		DetectionPolicy:      {},
		DetectionDirect:      {},
	}
}

func AllowedConfidences() map[string]struct{} {
	return map[string]struct{}{
		ConfidenceLow:    {},
		ConfidenceMedium: {},
		ConfidenceHigh:   {},
	}
}

func AllowedSeverities() map[Severity]struct{} {
	return map[Severity]struct{}{
		SeverityInfo:     {},
		SeverityWarning:  {},
		SeverityCritical: {},
	}
}

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

func NormalizeIssue(issue Issue) Issue {
	issue.Kind = strings.TrimSpace(issue.Kind)
	issue.Namespace = strings.TrimSpace(issue.Namespace)
	issue.Name = strings.TrimSpace(issue.Name)
	issue.Check = strings.TrimSpace(issue.Check)
	issue.Summary = strings.TrimSpace(issue.Summary)
	issue.Recommendation = strings.TrimSpace(issue.Recommendation)
	issue.Category = strings.TrimSpace(issue.Category)
	issue.Detection = strings.TrimSpace(strings.ToLower(issue.Detection))
	issue.Confidence = strings.TrimSpace(strings.ToLower(issue.Confidence))
	if issue.Category == "" {
		issue.Category = CategoryForKind(issue.Kind)
	}
	if issue.Detection == "" {
		switch {
		case strings.Contains(issue.Check, "probe"):
			issue.Detection = DetectionActiveProbe
		case issue.Check != "":
			issue.Detection = DetectionHeuristic
		default:
			issue.Detection = DetectionDerived
		}
	}
	if issue.Confidence == "" {
		switch issue.Severity {
		case SeverityCritical:
			issue.Confidence = ConfidenceHigh
		case SeverityWarning:
			issue.Confidence = ConfidenceMedium
		default:
			issue.Confidence = ConfidenceLow
		}
		if issue.Detection == DetectionPolicy || issue.Detection == DetectionDirect {
			issue.Confidence = ConfidenceHigh
		}
		if issue.Detection == DetectionActiveProbe && issue.Severity != SeverityCritical {
			issue.Confidence = ConfidenceMedium
		}
	}
	if len(issue.References) > 0 {
		refs := make([]string, 0, len(issue.References))
		seen := map[string]struct{}{}
		for _, ref := range issue.References {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			if _, ok := seen[ref]; ok {
				continue
			}
			seen[ref] = struct{}{}
			refs = append(refs, ref)
		}
		issue.References = refs
	}
	return issue
}

func ValidateIssuePolicy(issue Issue) error {
	issue = NormalizeIssue(issue)
	if _, ok := AllowedSeverities()[issue.Severity]; !ok {
		return fmt.Errorf("invalid severity %q", issue.Severity)
	}
	if issue.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	if issue.Summary == "" {
		return fmt.Errorf("summary is required")
	}
	if issue.Recommendation == "" {
		return fmt.Errorf("recommendation is required")
	}
	if _, ok := AllowedDetections()[issue.Detection]; !ok {
		return fmt.Errorf("invalid detection %q", issue.Detection)
	}
	if _, ok := AllowedConfidences()[issue.Confidence]; !ok {
		return fmt.Errorf("invalid confidence %q", issue.Confidence)
	}
	if issue.Category == "" {
		return fmt.Errorf("category is required")
	}
	return nil
}

func ValidateIssuesPolicy(issues []Issue) error {
	for index, issue := range issues {
		if err := ValidateIssuePolicy(issue); err != nil {
			return fmt.Errorf("issue %d: %w", index, err)
		}
	}
	return nil
}

func NormalizeIssues(issues []Issue) []Issue {
	if len(issues) == 0 {
		return nil
	}
	result := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		result = append(result, NormalizeIssue(issue))
	}
	return result
}
