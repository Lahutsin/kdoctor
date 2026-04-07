package diagnostics

import (
	"context"
	"net/http"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKnownCNI(t *testing.T) {
	if !isKnownCNI("calico-node") || !isKnownCNI("cilium-agent") || isKnownCNI("random-daemon") {
		t.Fatal("unexpected known CNI detection")
	}
}

func TestCheckCNIAndCSI(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		daemonsets []appsv1.DaemonSet
		drivers    []storagev1.CSIDriver
		wantCount  int
	}{
		{
			name: "unhealthy cni and csi with no drivers",
			daemonsets: []appsv1.DaemonSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: metav1.NamespaceSystem}, Status: appsv1.DaemonSetStatus{NumberAvailable: 1, DesiredNumberScheduled: 2}},
				{ObjectMeta: metav1.ObjectMeta{Name: "ebs-csi-node", Namespace: metav1.NamespaceSystem}, Status: appsv1.DaemonSetStatus{NumberAvailable: 0, DesiredNumberScheduled: 2}},
			},
			wantCount: 3,
		},
		{
			name:       "no known cni",
			daemonsets: []appsv1.DaemonSet{{ObjectMeta: metav1.ObjectMeta{Name: "node-exporter", Namespace: metav1.NamespaceSystem}, Status: appsv1.DaemonSetStatus{NumberAvailable: 1, DesiredNumberScheduled: 1}}},
			drivers:    []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "ebs.csi.aws.com"}}},
			wantCount:  1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/apis/apps/v1/namespaces/kube-system/daemonsets":
					writeJSONResponse(t, w, http.StatusOK, &appsv1.DaemonSetList{Items: test.daemonsets})
				case "/apis/storage.k8s.io/v1/csidrivers":
					writeJSONResponse(t, w, http.StatusOK, &storagev1.CSIDriverList{Items: test.drivers})
				default:
					writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
				}
			})

			issues, err := CheckCNIAndCSI(ctx, cs)
			if err != nil {
				t.Fatalf("CheckCNIAndCSI returned error: %v", err)
			}
			if len(issues) != test.wantCount {
				t.Fatalf("expected %d issues, got %+v", test.wantCount, issues)
			}
		})
	}
}
