package diagnostics

import (
	"bytes"
	"context"
	"fmt"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckWebhooks validates that webhook services are reachable and not misconfigured.
func CheckWebhooks(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	var issues []Issue

	vcfgs, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}
	if err == nil {
		for _, cfg := range vcfgs.Items {
			issues = append(issues, evaluateValidatingWebhook(ctx, cs, cfg)...)
		}
	}

	mcfgs, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}
	if err == nil {
		for _, cfg := range mcfgs.Items {
			issues = append(issues, evaluateMutatingWebhook(ctx, cs, cfg)...)
		}
	}

	return issues, nil
}

func evaluateValidatingWebhook(ctx context.Context, cs *kubernetes.Clientset, cfg admissionv1.ValidatingWebhookConfiguration) []Issue {
	issues := make([]Issue, 0)
	for _, wh := range cfg.Webhooks {
		issues = append(issues, evaluateWebhook(ctx, cs, cfg.Name, "ValidatingWebhookConfiguration", wh.ClientConfig, wh.FailurePolicy, wh.TimeoutSeconds, wh.Name)...)
	}
	return issues
}

func evaluateMutatingWebhook(ctx context.Context, cs *kubernetes.Clientset, cfg admissionv1.MutatingWebhookConfiguration) []Issue {
	issues := make([]Issue, 0)
	for _, wh := range cfg.Webhooks {
		issues = append(issues, evaluateWebhook(ctx, cs, cfg.Name, "MutatingWebhookConfiguration", wh.ClientConfig, wh.FailurePolicy, wh.TimeoutSeconds, wh.Name)...)
	}
	return issues
}

func evaluateWebhook(ctx context.Context, cs *kubernetes.Clientset, cfgName, kind string, clientConfig admissionv1.WebhookClientConfig, failurePolicy *admissionv1.FailurePolicyType, timeoutSeconds *int32, whName string) []Issue {
	issues := make([]Issue, 0)
	if clientConfig.Service == nil {
		return issues
	}

	svcNS := clientConfig.Service.Namespace
	svcName := clientConfig.Service.Name

	_, err := cs.CoreV1().Services(svcNS).Get(ctx, svcName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		issues = append(issues, Issue{
			Kind:           kind,
			Name:           cfgName,
			Severity:       SeverityCritical,
			Summary:        fmt.Sprintf("webhook %s service %s/%s missing", whName, svcNS, svcName),
			Recommendation: "Deploy or fix the webhook service endpoints, or set failurePolicy=Ignore to reduce impact.",
		})
		return issues
	}
	if err != nil {
		issues = append(issues, Issue{
			Kind:           kind,
			Name:           cfgName,
			Severity:       SeverityWarning,
			Summary:        fmt.Sprintf("webhook %s service lookup error: %v", whName, err),
			Recommendation: "Check API access to webhook namespaces and service permissions.",
		})
		return issues
	}

	eps, err := cs.CoreV1().Endpoints(svcNS).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil {
		if !hasReadyAddress(eps) {
			issues = append(issues, Issue{
				Kind:           kind,
				Name:           cfgName,
				Severity:       SeverityWarning,
				Summary:        fmt.Sprintf("webhook %s has no ready endpoints for service %s/%s", whName, svcNS, svcName),
				Recommendation: "Ensure webhook pods are running and endpoints are populated; check network policies and readiness probes.",
			})
		}
	}

	if clientConfig.CABundle == nil || len(clientConfig.CABundle) == 0 {
		issues = append(issues, Issue{
			Kind:           kind,
			Name:           cfgName,
			Severity:       SeverityInfo,
			Summary:        fmt.Sprintf("webhook %s missing caBundle", whName),
			Recommendation: "Populate caBundle or enable cert management to avoid TLS errors to the webhook service.",
		})
	}

	if failurePolicy != nil && *failurePolicy == admissionv1.Fail {
		issues = append(issues, Issue{
			Kind:           kind,
			Name:           cfgName,
			Severity:       SeverityInfo,
			Summary:        fmt.Sprintf("webhook %s uses failurePolicy=Fail", whName),
			Recommendation: "Confirm webhook availability; consider failurePolicy=Ignore for non-critical validations to reduce blast radius.",
		})
	}

	if timeoutSeconds != nil {
		if *timeoutSeconds > 15 {
			issues = append(issues, Issue{
				Kind:           kind,
				Name:           cfgName,
				Severity:       SeverityWarning,
				Summary:        fmt.Sprintf("webhook %s timeoutSeconds=%d may add admission latency", whName, *timeoutSeconds),
				Recommendation: "Consider lowering timeoutSeconds to 10s or less and ensure webhook endpoints are responsive.",
			})
		}
	} else {
		issues = append(issues, Issue{
			Kind:           kind,
			Name:           cfgName,
			Severity:       SeverityInfo,
			Summary:        fmt.Sprintf("webhook %s timeoutSeconds not set (defaults to 10s)", whName),
			Recommendation: "Set explicit timeoutSeconds to control admission latency and avoid blocking requests too long.",
		})
	}

	issues = append(issues, probeWebhookLatency(ctx, cs, svcNS, svcName)...)

	return issues
}

// probeWebhookLatency issues lightweight GET and AdmissionReview POST probes via the service proxy.
func probeWebhookLatency(ctx context.Context, cs *kubernetes.Clientset, ns, svc string) []Issue {
	var issues []Issue

	start := time.Now()
	res := cs.CoreV1().RESTClient().Get().Namespace(ns).Resource("services").Name(svc).SubResource("proxy").Do(ctx)
	if _, err := res.Raw(); err != nil {
		issues = append(issues, Issue{
			Kind:           "Webhook",
			Namespace:      ns,
			Name:           svc,
			Severity:       SeverityWarning,
			Summary:        fmt.Sprintf("webhook service %s/%s probe failed: %v", ns, svc, err),
			Recommendation: "Check webhook pod readiness, network policy, and service endpoints.",
		})
	}
	latency := time.Since(start)
	if latency > 1500*time.Millisecond {
		issues = append(issues, Issue{
			Kind:           "Webhook",
			Namespace:      ns,
			Name:           svc,
			Severity:       SeverityWarning,
			Summary:        fmt.Sprintf("webhook service %s/%s slow (~%dms)", ns, svc, latency.Milliseconds()),
			Recommendation: "Investigate webhook handler performance and network path; consider lowering timeoutSeconds.",
		})
	}

	// AdmissionReview POST probe (best-effort).
	admissionPayload := []byte(`{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","request":{"uid":"00000000-0000-0000-0000-000000000000","kind":{"group":"","version":"v1","kind":"Pod"},"resource":{"group":"","version":"v1","resource":"pods"},"operation":"CONNECT","object":{},"name":"","namespace":""}}`)
	postStart := time.Now()
	postReq := cs.CoreV1().RESTClient().Post().Namespace(ns).Resource("services").Name(svc).SubResource("proxy").Body(bytes.NewReader(admissionPayload)).SetHeader("Content-Type", "application/json")
	resp := postReq.Do(ctx)
	_, err := resp.Raw()
	postLatency := time.Since(postStart)
	if err != nil {
		issues = append(issues, Issue{
			Kind:           "Webhook",
			Namespace:      ns,
			Name:           svc,
			Severity:       SeverityWarning,
			Summary:        fmt.Sprintf("admission probe to %s/%s failed: %v", ns, svc, err),
			Recommendation: "Ensure webhook endpoint accepts admission reviews; verify TLS, service port, and readiness.",
		})
	} else if postLatency > 1500*time.Millisecond {
		issues = append(issues, Issue{
			Kind:           "Webhook",
			Namespace:      ns,
			Name:           svc,
			Severity:       SeverityWarning,
			Summary:        fmt.Sprintf("admission probe to %s/%s slow (~%dms)", ns, svc, postLatency.Milliseconds()),
			Recommendation: "Investigate webhook handler performance and network latency; consider lower timeoutSeconds.",
		})
	}

	return issues
}

func hasReadyAddress(eps *corev1.Endpoints) bool {
	for _, subset := range eps.Subsets {
		if len(subset.Addresses) > 0 {
			return true
		}
	}
	return false
}
