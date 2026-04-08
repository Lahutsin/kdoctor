package diagnostics

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIssueKeyAndCategoryHelpers(t *testing.T) {
	issue := Issue{Kind: "Pod", Namespace: "prod", Name: "api", Check: "crashloop", Summary: "restarting"}
	if issue.Key() != "Pod|prod|api|crashloop|restarting" {
		t.Fatalf("unexpected key: %q", issue.Key())
	}
	if issue.EffectiveCategory() != "workloads" {
		t.Fatalf("unexpected effective category: %q", issue.EffectiveCategory())
	}
	if got := (Issue{Kind: "Custom", Category: "security"}).EffectiveCategory(); got != "security" {
		t.Fatalf("expected explicit category override, got %q", got)
	}

	tests := map[string]string{
		"Pod":                            "workloads",
		"Node":                           "networking",
		"PVC":                            "storage",
		"Webhook":                        "security",
		"APIServer":                      "control-plane",
		"SomethingElse":                  "general",
		"ValidatingWebhookConfiguration": "security",
	}
	for kind, want := range tests {
		if got := CategoryForKind(kind); got != want {
			t.Fatalf("CategoryForKind(%q)=%q want %q", kind, got, want)
		}
	}
}

func TestIssueNormalizationAndPolicyValidation(t *testing.T) {
	issue := NormalizeIssue(Issue{
		Kind:           " Pod ",
		Severity:       SeverityWarning,
		Check:          "pods",
		Summary:        " restart loop ",
		Recommendation: " inspect rollout ",
	})
	if issue.Category != "workloads" {
		t.Fatalf("unexpected category: %+v", issue)
	}
	if issue.Detection != DetectionHeuristic || issue.Confidence != ConfidenceMedium {
		t.Fatalf("unexpected policy defaults: %+v", issue)
	}
	if err := ValidateIssuePolicy(issue); err != nil {
		t.Fatalf("ValidateIssuePolicy returned error: %v", err)
	}

	policyIssue := NormalizeIssue(Issue{
		Kind:           "Ingress",
		Severity:       SeverityInfo,
		Detection:      DetectionPolicy,
		Summary:        "probe disabled",
		Recommendation: "enable policy",
	})
	if policyIssue.Confidence != ConfidenceHigh {
		t.Fatalf("expected policy detection to default to high confidence, got %+v", policyIssue)
	}
}

func TestIssuePolicyValidationRejectsInvalidValues(t *testing.T) {
	if err := ValidateIssuePolicy(Issue{Kind: "Pod", Severity: Severity("bad"), Summary: "x", Recommendation: "y"}); err == nil {
		t.Fatal("expected invalid severity to fail validation")
	}
	if err := ValidateIssuePolicy(Issue{Kind: "Pod", Severity: SeverityWarning, Detection: "magic", Summary: "x", Recommendation: "y"}); err == nil {
		t.Fatal("expected invalid detection to fail validation")
	}
	if err := ValidateIssuePolicy(Issue{Kind: "Pod", Severity: SeverityWarning, Confidence: "certain", Summary: "x", Recommendation: "y"}); err == nil {
		t.Fatal("expected invalid confidence to fail validation")
	}
}

func TestIssuePolicyAcrossRepresentativeChecks(t *testing.T) {
	issues := []Issue{}
	issues = append(issues, SkippedProbeIssue("Ingress", "prod", "api", "ingress-probe", "skipped", "enable probes"))
	issues = append(issues, suspiciousRestartPatternIssues([]corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute))},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", RestartCount: 4}}},
	}})...)
	issues = append(issues, gpuNodeInventoryIssues([]corev1.Node{{
		ObjectMeta: metav1.ObjectMeta{Name: "gpu-a", Labels: map[string]string{"nvidia.com/gpu.present": "true"}},
	}}, map[string]gpuResourceInventory{"gpu-a": {}})...)
	if len(issues) == 0 {
		t.Fatal("expected representative issues")
	}
	if err := ValidateIssuesPolicy(NormalizeIssues(issues)); err != nil {
		t.Fatalf("representative issue set failed validation: %v", err)
	}
}
