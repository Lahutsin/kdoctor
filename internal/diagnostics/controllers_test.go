package diagnostics

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestControllerHelpers(t *testing.T) {
	if !failedCondition([]batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}) {
		t.Fatal("expected failed job condition")
	}
	suspend := true
	issues := evaluateCronJobsV1([]batchv1.CronJob{{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "prod"}, Spec: batchv1.CronJobSpec{Suspend: &suspend}}, {ObjectMeta: metav1.ObjectMeta{Name: "cleanup", Namespace: "prod"}, Status: batchv1.CronJobStatus{LastScheduleTime: &metav1.Time{Time: time.Now().Add(-2 * time.Hour)}}}})
	if len(issues) != 2 {
		t.Fatalf("expected cronjob issues, got %+v", issues)
	}
	if int64Ptr(5) == nil || *int64Ptr(5) != 5 {
		t.Fatal("unexpected int64Ptr")
	}
	if summarizePodState(context.Background(), nil, nil) != "" {
		t.Fatal("expected nil pod summary to be empty")
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", UID: types.UID("uid-1")}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "Unschedulable"}}}}
	if !strings.Contains(summarizePodState(context.Background(), nil, pod), "unschedulable") {
		t.Fatal("expected unschedulable pod summary")
	}
}

func TestCheckControllers(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/apps/v1/namespaces/prod/deployments":
			zero := int32(0)
			one := int32(1)
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{Items: []appsv1.Deployment{{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
				Spec:       appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
				Status:     appsv1.DeploymentStatus{AvailableReplicas: 0},
			}, {
				ObjectMeta: metav1.ObjectMeta{Name: "idle", Namespace: "prod"},
				Spec:       appsv1.DeploymentSpec{Replicas: &zero, Paused: true},
			}}})
		case "/apis/apps/v1/namespaces/prod/daemonsets":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DaemonSetList{Items: []appsv1.DaemonSet{{ObjectMeta: metav1.ObjectMeta{Name: "node-agent", Namespace: "prod"}, Spec: appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, NumberAvailable: 1}}}})
		case "/apis/apps/v1/namespaces/prod/replicasets":
			zero := int32(0)
			one := int32(1)
			writeJSONResponse(t, w, http.StatusOK, &appsv1.ReplicaSetList{Items: []appsv1.ReplicaSet{{
				ObjectMeta: metav1.ObjectMeta{Name: "rs-web", Namespace: "prod"},
				Spec:       appsv1.ReplicaSetSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
				Status:     appsv1.ReplicaSetStatus{ReadyReplicas: 0},
			}, {
				ObjectMeta: metav1.ObjectMeta{Name: "rs-idle", Namespace: "prod"},
				Spec:       appsv1.ReplicaSetSpec{Replicas: &zero},
			}}})
		case "/apis/batch/v1/namespaces/prod/jobs":
			writeJSONResponse(t, w, http.StatusOK, &batchv1.JobList{Items: []batchv1.Job{{ObjectMeta: metav1.ObjectMeta{Name: "failed-job", Namespace: "prod"}, Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}}}, {ObjectMeta: metav1.ObjectMeta{Name: "warn-job", Namespace: "prod"}, Status: batchv1.JobStatus{Failed: 2}}}})
		case "/apis/batch/v1/namespaces/prod/cronjobs":
			suspend := true
			writeJSONResponse(t, w, http.StatusOK, &batchv1.CronJobList{Items: []batchv1.CronJob{{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "prod"}, Spec: batchv1.CronJobSpec{Suspend: &suspend}}, {ObjectMeta: metav1.ObjectMeta{Name: "cleanup", Namespace: "prod"}, Status: batchv1.CronJobStatus{LastScheduleTime: &metav1.Time{Time: time.Now().Add(-2 * time.Hour)}}}}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "prod", UID: types.UID("uid-1"), Labels: map[string]string{"app": "web"}},
				Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "web",
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "cannot pull image"}},
				}}},
			}}})
		case "/api/v1/namespaces/prod/events":
			writeJSONResponse(t, w, http.StatusOK, &corev1.EventList{Items: []corev1.Event{{Reason: "BackOff", Message: "failed container", InvolvedObject: corev1.ObjectReference{Name: "web-0", UID: types.UID("uid-1")}}}})
		case "/api/v1/namespaces/prod/pods/web-0/log":
			_, _ = w.Write([]byte("line1\nline2\nline3\nline4"))
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckControllers(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckControllers returned error: %v", err)
	}
	if len(issues) < 8 {
		t.Fatalf("expected multiple controller issues, got %+v", issues)
	}
	if detail := samplePodIssue(ctx, cs, "prod", map[string]string{"app": "web"}); !strings.Contains(detail, "web-0") {
		t.Fatalf("expected sampled pod detail, got %q", detail)
	}
	if evidence := fetchPodEvidence(ctx, cs, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "prod", UID: types.UID("uid-1")}}, "web"); !strings.Contains(evidence, "events:") {
		t.Fatalf("expected pod evidence, got %q", evidence)
	}
}
