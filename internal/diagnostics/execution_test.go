package diagnostics

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestExecutionHelpers(t *testing.T) {
	policy := NormalizeProbePolicy(ProbePolicy{TLSProbeMode: " VERIFY ", TargetClasses: nil})
	if policy.TLSProbeMode != "verify" || policy.TargetClasses == nil {
		t.Fatalf("unexpected normalized policy: %+v", policy)
	}
	policy = NormalizeProbePolicy(ProbePolicy{TLSProbeMode: "broken", TargetClasses: map[string]bool{"ingress": true}})
	if policy.TLSProbeMode != "handshake-only" {
		t.Fatalf("expected fallback tls probe mode, got %+v", policy)
	}

	SetProbePolicy(ProbePolicy{EnableActiveProbes: true, EnableHostNetworkProbes: true, TargetClasses: map[string]bool{"ingress": true}, TLSProbeMode: "verify"})
	t.Cleanup(func() {
		SetProbePolicy(defaultProbePolicy())
	})
	if !ActiveProbeEnabled("ingress") || HostNetworkProbeEnabled("webhook") || TLSProbeMode() != "verify" {
		t.Fatalf("unexpected active probe policy behavior: %+v", CurrentProbePolicy())
	}
	if probeTargetAllowed(map[string]bool{}, "") != true || probeTargetAllowed(map[string]bool{"node": true}, "") != false {
		t.Fatal("unexpected probe target allow logic")
	}

	issue := SkippedProbeIssue("Ingress", "prod", "api", "ingress-handshake", "skipped", "enable probes")
	if issue.Detection != "policy" || issue.Confidence != "high" {
		t.Fatalf("unexpected skipped probe issue: %+v", issue)
	}

	if !errors.Is(NotApplicableError("namespace scoped"), ErrNotApplicable) || !errors.Is(NotApplicableError(""), ErrNotApplicable) {
		t.Fatal("expected wrapped not-applicable errors")
	}

	if status, code, hint := ClassifyExecutionError(nil); status != ExecutionStatusOK || code != "" || hint {
		t.Fatalf("unexpected nil error classification: %s %s %v", status, code, hint)
	}
	if status, code, hint := ClassifyExecutionError(NotApplicableError("prod")); status != ExecutionStatusNotApplicable || code != "not_applicable" || hint {
		t.Fatalf("unexpected not-applicable classification: %s %s %v", status, code, hint)
	}
	forbidden := apierrors.NewForbidden(schema.GroupResource{Group: "", Resource: "pods"}, "api", errors.New("forbidden"))
	if status, code, hint := ClassifyExecutionError(forbidden); status != ExecutionStatusSkipped || code != "rbac_denied" || !hint {
		t.Fatalf("unexpected forbidden classification: %s %s %v", status, code, hint)
	}
	if status, code, hint := ClassifyExecutionError(context.DeadlineExceeded); status != ExecutionStatusError || code != "timeout" || hint {
		t.Fatalf("unexpected timeout classification: %s %s %v", status, code, hint)
	}
	if status, code, hint := ClassifyExecutionError(errors.New("boom")); status != ExecutionStatusError || code != "check_failed" || hint {
		t.Fatalf("unexpected generic classification: %s %s %v", status, code, hint)
	}

	if got := OverallExecutionStatus(nil); got != ExecutionStatusOK {
		t.Fatalf("expected ok status for empty records, got %s", got)
	}
	if got := OverallExecutionStatus([]ExecutionRecord{{Status: ExecutionStatusFinding}}); got != ExecutionStatusFinding {
		t.Fatalf("expected finding status, got %s", got)
	}
	if got := OverallExecutionStatus([]ExecutionRecord{{Status: ExecutionStatusSkipped}}); got != ExecutionStatusPartial {
		t.Fatalf("expected partial status for skipped checks, got %s", got)
	}
	if got := OverallExecutionStatus([]ExecutionRecord{{Status: ExecutionStatusFinding}, {Status: ExecutionStatusError}}); got != ExecutionStatusPartial {
		t.Fatalf("expected partial status for errors, got %s", got)
	}
}

func TestExecutionSummaryJSONShapes(t *testing.T) {
	record := ExecutionRecord{Name: "pods", Scope: "check", Status: ExecutionStatusSkipped, ErrorCode: "rbac_denied", PermissionHint: true}
	if record.Name != "pods" || record.Scope != "check" || record.Status != ExecutionStatusSkipped || !record.PermissionHint {
		t.Fatalf("unexpected execution record: %+v", record)
	}
	summary := ExecutionSummary{Status: ExecutionStatusPartial, Checks: []ExecutionRecord{record}, StartedAt: metav1.Now().Time, FinishedAt: metav1.Now().Time}
	if summary.Status != ExecutionStatusPartial || len(summary.Checks) != 1 {
		t.Fatalf("unexpected execution summary: %+v", summary)
	}
}
