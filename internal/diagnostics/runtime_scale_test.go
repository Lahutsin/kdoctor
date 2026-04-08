package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPagedListRespectsChunkingAndContinue(t *testing.T) {
	ctx := withRuntimeContext(context.Background(), RuntimeOptions{ListChunkSize: 3, MaxListItems: 20}, newRuntimeLogger("off", "test"), "test")
	items, err := pagedList(ctx, "pods", func(opts metav1.ListOptions) ([]int, string, error) {
		start := 0
		if opts.Continue != "" {
			parsed, convErr := strconv.Atoi(opts.Continue)
			if convErr != nil {
				return nil, "", convErr
			}
			start = parsed
		}
		if opts.Limit != 3 {
			t.Fatalf("expected chunk limit 3, got %d", opts.Limit)
		}
		end := start + int(opts.Limit)
		if end > 8 {
			end = 8
		}
		page := make([]int, 0, end-start)
		for value := start; value < end; value++ {
			page = append(page, value)
		}
		next := ""
		if end < 8 {
			next = strconv.Itoa(end)
		}
		return page, next, nil
	})
	if err != nil {
		t.Fatalf("pagedList returned error: %v", err)
	}
	if len(items) != 8 || items[0] != 0 || items[7] != 7 {
		t.Fatalf("unexpected paged result: %+v", items)
	}
}

func TestPagedListMemoryGuardrail(t *testing.T) {
	ctx := withRuntimeContext(context.Background(), RuntimeOptions{ListChunkSize: 2, MaxListItems: 5}, newRuntimeLogger("off", "test"), "test")
	_, err := pagedList(ctx, "pods", func(opts metav1.ListOptions) ([]int, string, error) {
		start := 0
		if opts.Continue != "" {
			start, _ = strconv.Atoi(opts.Continue)
		}
		end := start + int(opts.Limit)
		if end > 6 {
			end = 6
		}
		page := make([]int, 0, end-start)
		for value := start; value < end; value++ {
			page = append(page, value)
		}
		next := ""
		if end < 6 {
			next = strconv.Itoa(end)
		}
		return page, next, nil
	})
	if err == nil || !strings.Contains(err.Error(), "memory guardrail") {
		t.Fatalf("expected memory guardrail error, got %v", err)
	}
}

func TestWithRetryRetriesTransientFailures(t *testing.T) {
	ctx := withRuntimeContext(context.Background(), RuntimeOptions{RetryAttempts: 3, RetryInitialBackoffMS: 1}, newRuntimeLogger("off", "retry"), "retry")
	attempts := 0
	err := withRetry(ctx, "pods", func() error {
		attempts++
		if attempts < 3 {
			return apierrors.NewServiceUnavailable("temporary")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withRetry returned error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestListPodsCachedReusesAPIResult(t *testing.T) {
	var podCalls int32
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/pods":
			atomic.AddInt32(&podCalls, 1)
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"}}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	ctx := withRuntimeContext(context.Background(), RuntimeOptions{}, newRuntimeLogger("off", "cache"), "cache")
	items, err := listPodsCached(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("first listPodsCached returned error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("unexpected pod count: %d", len(items))
	}
	items, err = listPodsCached(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("second listPodsCached returned error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("unexpected pod count after cache reuse: %d", len(items))
	}
	if got := atomic.LoadInt32(&podCalls); got != 1 {
		t.Fatalf("expected single API call due to cache reuse, got %d", got)
	}
}

func TestCollectCapabilityPreflightPartial(t *testing.T) {
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		var review authorizationv1.SelfSubjectAccessReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			t.Fatalf("decode review: %v", err)
		}
		resource := review.Spec.ResourceAttributes.Resource
		allowed := resource != "nodes"
		reason := "granted"
		if !allowed {
			reason = "denied"
		}
		writeJSONResponse(t, w, http.StatusCreated, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: allowed, Reason: reason}})
	})
	ctx := withRuntimeContext(context.Background(), RuntimeOptions{RetryAttempts: 1}, newRuntimeLogger("off", "preflight"), "preflight")
	summary := collectCapabilityPreflight(ctx, cs, "prod")
	if summary.Status != ExecutionStatusPartial {
		t.Fatalf("expected partial status, got %+v", summary)
	}
	if len(summary.Checks) == 0 {
		t.Fatalf("expected preflight checks, got %+v", summary)
	}
	seenDenied := false
	for _, check := range summary.Checks {
		if check.Resource == "nodes" && !check.Allowed {
			seenDenied = true
		}
	}
	if !seenDenied {
		t.Fatalf("expected denied nodes capability, got %+v", summary)
	}
}

func TestRuntimeRoundTripperRetriesAndLimits(t *testing.T) {
	var calls int32
	rt := &runtimeRoundTripper{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			current := atomic.AddInt32(&calls, 1)
			if current < 3 {
				return nil, apierrors.NewServiceUnavailable("retry")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
		}),
		limiter: make(chan struct{}, 1),
		retries: 3,
		backoff: time.Millisecond,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("unexpected round trip result: status=%d calls=%d", resp.StatusCode, calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestTransientErrorClassification(t *testing.T) {
	if !isTransientError(apierrors.NewTooManyRequests("throttle", 1)) {
		t.Fatal("expected too many requests to be transient")
	}
	if !isTransientError(errors.New("connection reset by peer")) {
		t.Fatal("expected connection reset to be transient")
	}
	if isTransientError(errors.New("permanent failure")) {
		t.Fatal("expected permanent failure to be non-transient")
	}
}
