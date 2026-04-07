package diagnostics

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWebhookHelpersAndCheckWebhooks(t *testing.T) {
	expired := generateSelfSignedCertPEM(t, "webhook.prod.svc", time.Now().Add(-time.Hour))
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "webhook", Namespace: "prod"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Selector: map[string]string{"app": "webhook"}}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "webhook-pod", Namespace: "prod", Labels: map[string]string{"app": "webhook"}}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "webhook-tls"}}}}}}
	secret := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "webhook-tls", Namespace: "prod"}, Data: map[string][]byte{"tls.crt": expired}}
	rules := []admissionv1.RuleWithOperations{{
		Operations: []admissionv1.OperationType{admissionv1.OperationAll},
		Rule:       admissionv1.Rule{APIGroups: []string{"*"}, Resources: []string{"pods", "secrets"}},
	}}
	eval := webhookEvaluation{kind: "MutatingWebhookConfiguration", cfgName: "mutator", webhookName: "injector", clientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "webhook", Namespace: "prod"}, CABundle: expired}, failurePolicy: admissionv1.Fail, timeoutSeconds: 20, rules: rules}
	inventory := webhookInventory{services: map[string]corev1.Service{"prod/webhook": service}, endpoints: map[string]*corev1.Endpoints{"prod/webhook": {}}, podsByNS: map[string][]corev1.Pod{"prod": {pod}}, secretsByNS: map[string][]corev1.Secret{"prod": {secret}}, namespaces: map[string]namespaceMeta{"prod": {name: "prod"}}}

	if effectiveFailurePolicy(nil) != admissionv1.Fail || effectiveTimeoutSeconds(nil) != 10 || !labelSelectorHasRequirements(&metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}) {
		t.Fatal("unexpected webhook policy helper behavior")
	}
	if len(webhookCABundleIssues(eval)) == 0 || len(webhookServingCertificateIssues(eval, service, inventory)) == 0 {
		t.Fatal("expected webhook certificate issues")
	}
	if len(webhookFailurePolicyIssues(webhookEvaluation{kind: "ValidatingWebhookConfiguration", cfgName: "validator", webhookName: "policy", failurePolicy: admissionv1.Ignore, rules: rules}, false)) == 0 {
		t.Fatal("expected failure policy issues")
	}
	if len(broadWebhookRuleIssues(eval)) == 0 || len(sensitiveWebhookControlIssues(webhookEvaluation{kind: "ValidatingWebhookConfiguration", cfgName: "validator", webhookName: "policy", rules: rules})) == 0 || len(mutatingSecurityContextIssues(eval)) == 0 {
		t.Fatal("expected broad and sensitive webhook issues")
	}
	if !webhookNeedsEnforcement(webhookEvaluation{kind: "ValidatingWebhookConfiguration", webhookName: "policy", rules: rules}) || !webhookHasHighDoSRisk(eval, false) || webhookHasExplicitControls(eval) {
		t.Fatal("unexpected webhook scope helper behavior")
	}
	if !webhookRulesClusterWide(rules) || !webhookTouchesSensitiveAdminResources(rules) || !webhookTouchesSecurityResources(rules) || !webhookTouchesPodResources(rules) {
		t.Fatal("expected webhook resource detection")
	}
	if !containsOperationInRules(rules, admissionv1.OperationAll) || !containsOperation([]admissionv1.OperationType{admissionv1.Create}, admissionv1.Create) || !webhookLooksLikeSecurityContextMutator(eval) {
		t.Fatal("unexpected webhook operation helper behavior")
	}
	if len(serviceSelectedPods(service, []corev1.Pod{pod})) != 1 || len(podReferencedSecrets(pod)) != 1 || len(webhookServiceDNSNames(service)) != 4 {
		t.Fatal("expected service and secret selection behavior")
	}
	if !secretLooksLikeWebhookCertificate(secret, webhookServiceDNSNames(service)) || !certificateMatchesAnyDNSName(parsePEMCertificates(expired)[0], webhookServiceDNSNames(service)) || !hasReadyAddress(&corev1.Endpoints{Subsets: []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}}}) {
		t.Fatal("expected webhook certificate helpers")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/namespaces":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NamespaceList{Items: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "prod"}}}})
		case r.URL.Path == "/api/v1/services":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceList{Items: []corev1.Service{service}})
		case r.URL.Path == "/api/v1/endpoints":
			writeJSONResponse(t, w, http.StatusOK, &corev1.EndpointsList{Items: []corev1.Endpoints{{ObjectMeta: metav1.ObjectMeta{Name: "webhook", Namespace: "prod"}}}})
		case r.URL.Path == "/api/v1/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		case r.URL.Path == "/api/v1/secrets":
			writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{Items: []corev1.Secret{secret}})
		case r.URL.Path == "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
			ignore := admissionv1.Ignore
			writeJSONResponse(t, w, http.StatusOK, &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{{ObjectMeta: metav1.ObjectMeta{Name: "validator"}, Webhooks: []admissionv1.ValidatingWebhook{{Name: "policy", FailurePolicy: &ignore, ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "webhook", Namespace: "prod"}, CABundle: expired}, Rules: rules}}}}})
		case r.URL.Path == "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations":
			writeJSONResponse(t, w, http.StatusOK, &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{{ObjectMeta: metav1.ObjectMeta{Name: "mutator"}, Webhooks: []admissionv1.MutatingWebhook{{Name: "injector", ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "webhook", Namespace: "prod"}, CABundle: expired}, TimeoutSeconds: func() *int32 { v := int32(20); return &v }(), Rules: rules}}}}})
		case strings.Contains(r.URL.Path, "/services/webhook/proxy"):
			writeJSONResponse(t, w, http.StatusOK, map[string]bool{"ok": true})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	issues, err := CheckWebhooks(ctx, cs)
	if err != nil {
		t.Fatalf("CheckWebhooks returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected webhook issues, got %+v", issues)
	}
	if _, err := CheckWebhooks(ctx, nil); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}