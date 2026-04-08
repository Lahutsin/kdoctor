package diagnostics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func BenchmarkPagedListLargeInventory(b *testing.B) {
	ctx := withRuntimeContext(context.Background(), RuntimeOptions{ListChunkSize: 250, MaxListItems: 20000}, newRuntimeLogger("off", "bench"), "bench")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := pagedList(ctx, "pods", func(opts metav1.ListOptions) ([]int, string, error) {
			start := 0
			if opts.Continue != "" {
				start, _ = strconv.Atoi(opts.Continue)
			}
			end := start + int(opts.Limit)
			if end > 5000 {
				end = 5000
			}
			items := make([]int, end-start)
			for index := range items {
				items[index] = start + index
			}
			next := ""
			if end < 5000 {
				next = strconv.Itoa(end)
			}
			return items, next, nil
		})
		if err != nil {
			b.Fatalf("pagedList returned error: %v", err)
		}
	}
}

func BenchmarkListPodsCachedReuse(b *testing.B) {
	var podCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/pods":
			atomic.AddInt32(&podCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(&corev1.PodList{Items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		b.Fatalf("create clientset: %v", err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctx := withRuntimeContext(context.Background(), RuntimeOptions{}, newRuntimeLogger("off", "bench"), "bench")
		if _, err := listPodsCached(ctx, cs, "prod"); err != nil {
			b.Fatalf("first cache fill failed: %v", err)
		}
		if _, err := listPodsCached(ctx, cs, "prod"); err != nil {
			b.Fatalf("cache reuse failed: %v", err)
		}
	}
	b.ReportMetric(float64(atomic.LoadInt32(&podCalls))/float64(b.N), "api-calls/op")
}

func BenchmarkNormalizeIssuesPolicy(b *testing.B) {
	issues := make([]Issue, 1000)
	for index := range issues {
		issues[index] = Issue{Kind: "Pod", Namespace: "prod", Name: "pod", Severity: SeverityWarning, Check: "pods", Summary: "restart", Recommendation: "investigate"}
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		normalized := NormalizeIssues(issues)
		if err := ValidateIssuesPolicy(normalized); err != nil {
			b.Fatalf("validate issues policy: %v", err)
		}
	}
}
