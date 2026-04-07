package diagnostics

import (
	"context"
	"net/http"
	"testing"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPDBHelpersAndCheckPDBs(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
	items := []policyv1.PodDisruptionBudget{
		{ObjectMeta: metav1.ObjectMeta{Name: "api-a", Namespace: "prod"}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: selector}, Status: policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0, ExpectedPods: 2}},
		{ObjectMeta: metav1.ObjectMeta{Name: "api-b", Namespace: "prod"}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: selector}},
		{ObjectMeta: metav1.ObjectMeta{Name: "empty-selector", Namespace: "prod"}},
	}
	selectors := map[string]string{
		"prod/api-a":          metav1.FormatLabelSelector(selector),
		"prod/api-b":          metav1.FormatLabelSelector(selector),
		"prod/empty-selector": "",
	}
	if len(detectPDBSelectorOverlap(items, selectors)) != 1 {
		t.Fatal("expected overlapping PDB selector issue")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/policy/v1/namespaces/prod/poddisruptionbudgets":
			writeJSONResponse(t, w, http.StatusOK, &policyv1.PodDisruptionBudgetList{Items: items})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"kind": "PodList", "apiVersion": "v1", "items": []any{}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckPDBs(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckPDBs returned error: %v", err)
	}
	if len(issues) < 4 {
		t.Fatalf("expected several PDB issues, got %+v", issues)
	}
}
