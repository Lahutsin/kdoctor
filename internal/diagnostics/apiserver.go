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

	start := time.Now()
	result := cs.Discovery().RESTClient().Get().AbsPath("/readyz").Do(ctx)
	var code int
	result.StatusCode(&code)
	_, err := result.Raw()
	duration := time.Since(start)

	if err != nil {
		summary := fmt.Sprintf("apiserver readyz failed (status %d)", code)
		return []Issue{newAPIServerIssue(summary, SeverityCritical, "Check API server pods/endpoints, control-plane health, and network connectivity.")}, nil
	}

	// Flag slow responses as a warning signal.
	if duration > 1500*time.Millisecond {
		summary := fmt.Sprintf("apiserver readyz is slow (~%dms)", duration.Milliseconds())
		return []Issue{newAPIServerIssue(summary, SeverityWarning, "Investigate control-plane load, etcd latency, or network congestion.")}, nil
	}

	return nil, nil
}

func newAPIServerIssue(summary string, sev Severity, rec string) Issue {
	return Issue{
		Kind:           "APIServer",
		Severity:       sev,
		Summary:        summary,
		Recommendation: rec,
	}
}
