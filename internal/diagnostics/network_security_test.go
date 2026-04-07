package diagnostics

import (
	"context"
	"net/http"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestNetworkSecurityHelpers(t *testing.T) {
	ns := namespaceMeta{name: "prod", labels: map[string]string{"environment": "production"}}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", Labels: map[string]string{"app": "api"}},
		Spec: corev1.PodSpec{
			Volumes:    []corev1.Volume{{Name: "secret", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "db"}}}},
			Containers: []corev1.Container{{Name: "api", Env: []corev1.EnvVar{{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}}}}}}},
		},
	}
	defaultDeny := networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny", Namespace: "prod"}, Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, PodSelector: metav1.LabelSelector{}}}
	broadIngress := networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "broad-ing", Namespace: "prod"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}, Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}}}}}}
	port53 := intstr.FromInt(53)
	protoUDP := corev1.ProtocolUDP
	broadEgress := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "broad-eg", Namespace: "prod"},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}},
				Ports: []networkingv1.NetworkPolicyPort{{Port: &port53, Protocol: &protoUDP}},
			}},
		},
	}

	if !namespaceNeedsIsolation(ns, []corev1.Pod{pod}) || !namespaceHasDefaultDeny([]networkingv1.NetworkPolicy{defaultDeny}, networkingv1.PolicyTypeIngress) {
		t.Fatal("expected namespace isolation helpers to match")
	}
	if len(broadPolicyIssues([]networkingv1.NetworkPolicy{broadIngress, broadEgress})) != 2 {
		t.Fatal("expected broad policy issues")
	}
	selected := selectingPoliciesForPod([]networkingv1.NetworkPolicy{broadIngress, broadEgress}, pod, networkingv1.PolicyTypeIngress)
	if len(selected) != 1 || !policyAllowsAllIngress(broadIngress) || !policyAllowsAllEgress(broadEgress) {
		t.Fatal("expected policy selection and allow-all detection")
	}
	if !policiesAllowAllIngress([]networkingv1.NetworkPolicy{broadIngress}) || !policiesAllowAllEgress([]networkingv1.NetworkPolicy{broadEgress}) {
		t.Fatal("expected aggregate allow-all detection")
	}
	if !peerAllowsAllNamespaces(networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{}}) || !ipBlockAllowsAll(&networkingv1.IPBlock{CIDR: "0.0.0.0/0"}) {
		t.Fatal("expected peer and ipblock helpers to match")
	}
	if !hasOpenDNSEgress([]networkingv1.NetworkPolicy{broadEgress}) || !podConsumesSecrets(pod) {
		t.Fatal("expected DNS egress and secret-consumption detection")
	}
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "ingress-nginx", Namespace: "prod", Labels: map[string]string{"app": "ingress-nginx"}, Annotations: map[string]string{"whitelist-source-range": "10.0.0.0/8"}}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Ports: []corev1.ServicePort{{Name: "metrics", Port: 10254}}}}
	if !serviceHasAllowlist(service) || !looksLikeIngressController(service) || pointerProtocol(nil) != "" {
		t.Fatal("expected service/network helpers to match")
	}
	if len(sensitiveWorkloadExposureIssues([]corev1.Pod{pod}, ns, []networkingv1.NetworkPolicy{broadIngress, broadEgress})) == 0 {
		t.Fatal("expected sensitive workload exposure issues")
	}
	if len(webhookNetworkRestrictionIssues(map[string]struct{}{"prod/webhook-svc": {}}, map[string][]networkingv1.NetworkPolicy{"prod": {}}, map[string][]corev1.Pod{"prod": []corev1.Pod{pod}})) != 1 {
		t.Fatal("expected webhook restriction issue")
	}
	if len(loadBalancerExposureIssues([]corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "public", Namespace: "prod"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}}})) != 1 {
		t.Fatal("expected load balancer exposure issue")
	}
	if len(ingressControllerExposureIssues([]corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "ingress-nginx", Namespace: "prod", Labels: map[string]string{"app": "ingress-nginx"}}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Ports: []corev1.ServicePort{{Name: "metrics", Port: 10254}}}}})) != 1 {
		t.Fatal("expected ingress controller exposure issue")
	}
	if !policyCoversType(broadIngress, networkingv1.PolicyTypeIngress) || !ruleIncludesDNS(networkingv1.NetworkPolicyEgressRule{Ports: []networkingv1.NetworkPolicyPort{{Port: &port53, Protocol: &protoUDP}}}) || !policyReferencesSomePods(broadIngress, []corev1.Pod{pod}) || !peerAllowsAll(networkingv1.NetworkPolicyPeer{}) {
		t.Fatal("expected additional network helper coverage")
	}
}

func TestReferencedWebhookServices(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
			writeJSONResponse(t, w, http.StatusOK, &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{{Webhooks: []admissionv1.ValidatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "validator", Namespace: "prod"}}}}}}})
		case "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations":
			writeJSONResponse(t, w, http.StatusOK, &admissionv1.MutatingWebhookConfigurationList{Items: []admissionv1.MutatingWebhookConfiguration{{Webhooks: []admissionv1.MutatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "mutator", Namespace: "prod"}}}}}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	refs, err := referencedWebhookServices(ctx, cs)
	if err != nil {
		t.Fatalf("referencedWebhookServices returned error: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 referenced webhook services, got %+v", refs)
	}
}

func TestCheckNetworkSecurity(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		case "/apis/networking.k8s.io/v1/namespaces/prod/networkpolicies":
			writeJSONResponse(t, w, http.StatusOK, &networkingv1.NetworkPolicyList{})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", Labels: map[string]string{"app": "api"}},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "api",
					EnvFrom: []corev1.EnvFromSource{{
						SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}},
					}},
				}}},
			}}})
		case "/api/v1/namespaces/prod/services":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceList{Items: []corev1.Service{{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-nginx", Namespace: "prod", Labels: map[string]string{"app": "ingress-nginx"}},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Ports: []corev1.ServicePort{{Name: "metrics", Port: 10254}}},
			}, {
				ObjectMeta: metav1.ObjectMeta{Name: "public-app", Namespace: "prod"},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			}}})
		case "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
			writeJSONResponse(t, w, http.StatusOK, &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{{
				ObjectMeta: metav1.ObjectMeta{Name: "validate"},
				Webhooks: []admissionv1.ValidatingWebhook{{
					Name:         "v1.validate",
					ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Name: "webhook-svc", Namespace: "prod"}},
				}},
			}}})
		case "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations":
			writeJSONResponse(t, w, http.StatusOK, &admissionv1.MutatingWebhookConfigurationList{})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckNetworkSecurity(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckNetworkSecurity returned error: %v", err)
	}
	if len(issues) < 5 {
		t.Fatalf("expected several network security issues, got %+v", issues)
	}
	if _, err := CheckNetworkSecurity(ctx, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
