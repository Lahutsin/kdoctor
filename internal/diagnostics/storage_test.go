package diagnostics

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckStorage(t *testing.T) {
	ctx := context.Background()
	className := "fast"
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/persistentvolumeclaims":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PersistentVolumeClaimList{Items: []corev1.PersistentVolumeClaim{{
				ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "prod"},
				Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
			}, {
				ObjectMeta: metav1.ObjectMeta{Name: "implicit-class", Namespace: "prod"},
				Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: nil},
			}}})
		case "/api/v1/persistentvolumes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PersistentVolumeList{Items: []corev1.PersistentVolume{{
				ObjectMeta: metav1.ObjectMeta{Name: "released-pv"},
				Status:     corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
				Spec:       corev1.PersistentVolumeSpec{StorageClassName: className},
			}, {
				ObjectMeta: metav1.ObjectMeta{Name: "available-pv"},
				Status:     corev1.PersistentVolumeStatus{Phase: corev1.VolumeAvailable},
			}}})
		case "/apis/storage.k8s.io/v1/storageclasses":
			writeJSONResponse(t, w, http.StatusOK, &storagev1.StorageClassList{})
		case "/apis/storage.k8s.io/v1/volumeattachments":
			writeJSONResponse(t, w, http.StatusOK, &storagev1.VolumeAttachmentList{Items: []storagev1.VolumeAttachment{{
				ObjectMeta: metav1.ObjectMeta{Name: "attach-a"},
				Status:     storagev1.VolumeAttachmentStatus{Attached: false},
			}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckStorage(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckStorage returned error: %v", err)
	}
	if len(issues) < 5 {
		t.Fatalf("expected several storage issues, got %+v", issues)
	}
}
