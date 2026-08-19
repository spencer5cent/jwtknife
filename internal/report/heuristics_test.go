package report

import "testing"

func TestIsAdminSuccessRequiresAuthenticatedBoundary(t *testing.T) {
	base := &Baseline{
		Public: &HTTPObs{Status: 200, BodyLen: 4096, BodySHA256: "public"},
		Admin:  &HTTPObs{Status: 200, BodyLen: 4096, BodySHA256: "public"},
	}
	got := &HTTPObs{Status: 200, BodyLen: 4096, BodySHA256: "public"}
	if IsAdminSuccess(base, got) {
		t.Fatal("generic public 200 response must not count as admin access")
	}
}

func TestIsAdminSuccessMatchesRealTokenResponse(t *testing.T) {
	base := &Baseline{
		Public: &HTTPObs{Status: 401, BodyLen: 80, BodySHA256: "public"},
		Admin:  &HTTPObs{Status: 200, BodyLen: 240, BodySHA256: "admin"},
	}
	got := &HTTPObs{Status: 200, BodyLen: 240, BodySHA256: "admin"}
	if !IsAdminSuccess(base, got) {
		t.Fatal("forged response matching a distinct real-token response should count")
	}
}

func TestIsAdminSuccessRejectsSameLengthDifferentBody(t *testing.T) {
	base := &Baseline{
		Public: &HTTPObs{Status: 200, BodyLen: 240, BodySHA256: "public"},
		Admin:  &HTTPObs{Status: 200, BodyLen: 240, BodySHA256: "admin"},
	}
	got := &HTTPObs{Status: 200, BodyLen: 240, BodySHA256: "other"}
	if IsAdminSuccess(base, got) {
		t.Fatal("same status and length without matching authenticated content is not proof")
	}
}
