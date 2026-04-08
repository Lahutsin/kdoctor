package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

var ErrNotApplicable = errors.New("not applicable")

type ExecutionStatus string

const (
	ExecutionStatusOK            ExecutionStatus = "ok"
	ExecutionStatusFinding       ExecutionStatus = "finding"
	ExecutionStatusSkipped       ExecutionStatus = "skipped"
	ExecutionStatusError         ExecutionStatus = "error"
	ExecutionStatusNotApplicable ExecutionStatus = "not-applicable"
	ExecutionStatusPartial       ExecutionStatus = "partial"
)

type ExecutionRecord struct {
	Name           string          `json:"name"`
	Scope          string          `json:"scope"`
	Status         ExecutionStatus `json:"status"`
	DurationMS     int64           `json:"durationMs,omitempty"`
	IssueCount     int             `json:"issueCount,omitempty"`
	Slow           bool            `json:"slow,omitempty"`
	ErrorCode      string          `json:"errorCode,omitempty"`
	ErrorMessage   string          `json:"errorMessage,omitempty"`
	PermissionHint bool            `json:"permissionHint,omitempty"`
}

type ExecutionSummary struct {
	Status        ExecutionStatus   `json:"status"`
	TraceID       string            `json:"traceId,omitempty"`
	StartedAt     time.Time         `json:"startedAt"`
	FinishedAt    time.Time         `json:"finishedAt"`
	DurationMS    int64             `json:"durationMs"`
	APICalls      int64             `json:"apiCalls,omitempty"`
	Runtime       RuntimeStats      `json:"runtime,omitempty"`
	Preflight     CapabilitySummary `json:"preflight,omitempty"`
	Checks        []ExecutionRecord `json:"checks,omitempty"`
	Sections      []ExecutionRecord `json:"sections,omitempty"`
	SkippedChecks int               `json:"skippedChecks,omitempty"`
	ErroredChecks int               `json:"erroredChecks,omitempty"`
}

type RunResult struct {
	Issues     []Issue
	Execution  ExecutionSummary
	FirstError error
}

type ProbePolicy struct {
	EnableActiveProbes      bool            `json:"enableActiveProbes,omitempty"`
	EnableHostNetworkProbes bool            `json:"enableHostNetworkProbes,omitempty"`
	TargetClasses           map[string]bool `json:"targetClasses,omitempty"`
	TLSProbeMode            string          `json:"tlsProbeMode,omitempty"`
}

type probePolicyState struct {
	policy ProbePolicy
}

var activeProbePolicy atomic.Value

func init() {
	activeProbePolicy.Store(probePolicyState{policy: defaultProbePolicy()})
}

func defaultProbePolicy() ProbePolicy {
	return ProbePolicy{
		EnableActiveProbes:      false,
		EnableHostNetworkProbes: false,
		TargetClasses:           map[string]bool{},
		TLSProbeMode:            "handshake-only",
	}
}

func NormalizeProbePolicy(policy ProbePolicy) ProbePolicy {
	if policy.TargetClasses == nil {
		policy.TargetClasses = map[string]bool{}
	}
	policy.TLSProbeMode = strings.TrimSpace(strings.ToLower(policy.TLSProbeMode))
	switch policy.TLSProbeMode {
	case "", "handshake-only", "verify":
	default:
		policy.TLSProbeMode = "handshake-only"
	}
	return policy
}

func SetProbePolicy(policy ProbePolicy) {
	activeProbePolicy.Store(probePolicyState{policy: NormalizeProbePolicy(policy)})
}

func CurrentProbePolicy() ProbePolicy {
	state, _ := activeProbePolicy.Load().(probePolicyState)
	return state.policy
}

func ActiveProbeEnabled(targetClass string) bool {
	policy := CurrentProbePolicy()
	if !policy.EnableActiveProbes {
		return false
	}
	return probeTargetAllowed(policy.TargetClasses, targetClass)
}

func HostNetworkProbeEnabled(targetClass string) bool {
	policy := CurrentProbePolicy()
	if !policy.EnableHostNetworkProbes {
		return false
	}
	return probeTargetAllowed(policy.TargetClasses, targetClass)
}

func TLSProbeMode() string {
	return CurrentProbePolicy().TLSProbeMode
}

func probeTargetAllowed(targets map[string]bool, targetClass string) bool {
	if len(targets) == 0 {
		return true
	}
	if targetClass == "" {
		return false
	}
	return targets[targetClass]
}

func SkippedProbeIssue(kind, namespace, name, check, summary, recommendation string) Issue {
	return Issue{
		Kind:           kind,
		Namespace:      namespace,
		Name:           name,
		Severity:       SeverityInfo,
		Check:          check,
		Detection:      "policy",
		Confidence:     "high",
		Summary:        summary,
		Recommendation: recommendation,
	}
}

func NotApplicableError(reason string) error {
	if reason == "" {
		return ErrNotApplicable
	}
	return fmt.Errorf("%w: %s", ErrNotApplicable, reason)
}

func ClassifyExecutionError(err error) (ExecutionStatus, string, bool) {
	if err == nil {
		return ExecutionStatusOK, "", false
	}
	if errors.Is(err, ErrNotApplicable) {
		return ExecutionStatusNotApplicable, "not_applicable", false
	}
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || strings.Contains(strings.ToLower(err.Error()), "forbidden") || strings.Contains(strings.ToLower(err.Error()), "unauthorized") {
		return ExecutionStatusSkipped, "rbac_denied", true
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "deadline exceeded") || strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return ExecutionStatusError, "timeout", false
	}
	return ExecutionStatusError, "check_failed", false
}

func OverallExecutionStatus(records []ExecutionRecord) ExecutionStatus {
	status := ExecutionStatusOK
	for _, record := range records {
		switch record.Status {
		case ExecutionStatusError:
			return ExecutionStatusPartial
		case ExecutionStatusSkipped, ExecutionStatusNotApplicable:
			if status == ExecutionStatusOK {
				status = ExecutionStatusPartial
			}
		case ExecutionStatusFinding:
			if status == ExecutionStatusOK {
				status = ExecutionStatusFinding
			}
		}
	}
	return status
}
