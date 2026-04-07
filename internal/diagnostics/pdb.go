package diagnostics

import (
	"context"
	"fmt"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

func CheckPDBs(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	pdbs, err := cs.PolicyV1().PodDisruptionBudgets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)
	selectors := make(map[string]string, len(pdbs.Items))
	for _, pdb := range pdbs.Items {
		selector := metav1.FormatLabelSelector(pdb.Spec.Selector)
		selectors[pdb.Namespace+"/"+pdb.Name] = selector
		if pdb.Status.DisruptionsAllowed == 0 && pdb.Status.ExpectedPods > 0 {
			issues = append(issues, Issue{
				Kind:           "PDB",
				Namespace:      pdb.Namespace,
				Name:           pdb.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "pdb-disruptions",
				Summary:        fmt.Sprintf("PDB allows no disruptions (%d expected pods)", pdb.Status.ExpectedPods),
				Recommendation: "Review minAvailable/maxUnavailable before node drains or upgrades.",
			})
		}
		if selector == "" {
			issues = append(issues, Issue{
				Kind:           "PDB",
				Namespace:      pdb.Namespace,
				Name:           pdb.Name,
				Severity:       SeverityInfo,
				Category:       "workloads",
				Check:          "pdb-selector",
				Summary:        "PDB has an empty selector",
				Recommendation: "Verify the selector matches the intended pods; empty selectors can be surprising during maintenance.",
			})
			continue
		}
		if podCount := countSelectedPods(ctx, cs, pdb); podCount == 0 {
			issues = append(issues, Issue{
				Kind:           "PDB",
				Namespace:      pdb.Namespace,
				Name:           pdb.Name,
				Severity:       SeverityInfo,
				Category:       "workloads",
				Check:          "pdb-empty",
				Summary:        "PDB selector matches no pods",
				Recommendation: "Check whether the workload was renamed or the selector drifted from the workload labels.",
			})
		}
	}

	issues = append(issues, detectPDBSelectorOverlap(pdbs.Items, selectors)...)
	return issues, nil
}

func countSelectedPods(ctx context.Context, cs *kubernetes.Clientset, pdb policyv1.PodDisruptionBudget) int {
	if pdb.Spec.Selector == nil {
		return 0
	}
	selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil {
		return 0
	}
	pods, err := cs.CoreV1().Pods(pdb.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 1})
	if err != nil {
		return 0
	}
	return len(pods.Items)
}

func detectPDBSelectorOverlap(items []policyv1.PodDisruptionBudget, selectors map[string]string) []Issue {
	issues := make([]Issue, 0)
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[i].Namespace != items[j].Namespace {
				continue
			}
			left := selectors[items[i].Namespace+"/"+items[i].Name]
			right := selectors[items[j].Namespace+"/"+items[j].Name]
			if left == "" || right == "" || left != right {
				continue
			}
			issues = append(issues, Issue{
				Kind:           "PDB",
				Namespace:      items[i].Namespace,
				Name:           items[i].Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "pdb-overlap",
				Summary:        fmt.Sprintf("PDB selector overlaps with %s", items[j].Name),
				Recommendation: "Avoid overlapping PDB selectors unless disruption semantics are carefully planned.",
				References:     []string{labels.SelectorFromSet(map[string]string{"selector": left}).String()},
			})
		}
	}
	return issues
}
