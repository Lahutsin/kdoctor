package diagnostics

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestQuantityRatioBaseAndCheckResourceQuotas(t *testing.T) {
	if got := quantityRatioBase(resource.MustParse("1500m")); got <= 1.4 || got >= 1.6 {
		t.Fatalf("unexpected quantity ratio base: %v", got)
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(t, w, http.StatusOK, &corev1.ResourceQuotaList{Items: []corev1.ResourceQuota{{
			ObjectMeta: metav1.ObjectMeta{Name: "compute", Namespace: "prod"},
			Status: corev1.ResourceQuotaStatus{
				Hard: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("10"),
					corev1.ResourceMemory: resource.MustParse("10Gi"),
				},
				Used: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("8"),
					corev1.ResourceMemory: resource.MustParse("10Gi"),
				},
			},
		}}})
	})

	issues, err := CheckResourceQuotas(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckResourceQuotas returned error: %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("expected 2 quota issues, got %+v", issues)
	}
	hasCritical := false
	for _, issue := range issues {
		if issue.Severity == SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Fatalf("expected at least one critical quota issue, got %+v", issues)
	}
}
