package diagnostics

import "testing"

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
