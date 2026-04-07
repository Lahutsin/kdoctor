package diagnostics

import (
	"context"
	"fmt"
	"time"

	"k8s.io/client-go/kubernetes"
)

// CheckAPIServerHealth probes /readyz to detect API server unavailability or latency.
func CheckAPIServerHealth(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	if cs == nil || cs.Discovery() == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	issues := make([]Issue, 0)

	start := time.Now()
	result := cs.Discovery().RESTClient().Get().AbsPath("/readyz").Do(ctx)
	var code int
	result.StatusCode(&code)
	_, err := result.Raw()
	duration := time.Since(start)

	if err != nil {
		summary := fmt.Sprintf("apiserver readyz failed (status %d)", code)
		issues = append(issues, newAPIServerIssue(summary, SeverityCritical, "Check API server pods/endpoints, control-plane health, and network connectivity."))
	}

	// Flag slow responses as a warning signal.
	if err == nil && duration > 1500*time.Millisecond {
		summary := fmt.Sprintf("apiserver readyz is slow (~%dms)", duration.Milliseconds())
		issues = append(issues, newAPIServerIssue(summary, SeverityWarning, "Investigate control-plane load, etcd latency, or network congestion."))
	}

	issues = append(issues, CheckAPIExposure(ctx, cs)...)

	if len(issues) == 0 {
		return nil, nil
	}
	return issues, nil
}

func newAPIServerIssue(summary string, sev Severity, rec string) Issue {
	return Issue{
		Kind:           "APIServer",
		Severity:       sev,
		Category:       "control-plane",
		Check:          "apiserver",
		Summary:        summary,
		Recommendation: rec,
	}
}
