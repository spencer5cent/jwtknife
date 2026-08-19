package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEmptyJWTDoesNotSendAuthenticationPlacement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("ka_sessionid"); err == nil {
			t.Error("empty JWT public baseline sent an authentication cookie")
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("empty JWT public baseline sent Authorization")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(ClientOpts{Timeout: time.Second})
	result := client.Do(RequestPlan{
		URL:       server.URL,
		JWT:       "",
		Placement: JWTPlacement{Kind: PlaceCookie, Name: "ka_sessionid"},
	})
	if result.Err != "" || result.Status != http.StatusOK {
		t.Fatalf("unexpected response: %+v", result)
	}
}

func TestNormalizedBodyHashIgnoresNonceButKeepsAuthState(t *testing.T) {
	a := []byte(`<script nonce="aaaaaaaa1111+bbbbbbbb2222">window.state={logged_in:false}</script>`)
	b := []byte(`<script nonce="cccccccc3333+dddddddd4444">window.state={logged_in:false}</script>`)
	c := []byte(`<script nonce="eeeeeeee5555+ffffffff6666">window.state={logged_in:true}</script>`)
	if normalizedBodySHA256(a) != normalizedBodySHA256(b) {
		t.Fatal("changing nonce should not change normalized response identity")
	}
	if normalizedBodySHA256(a) == normalizedBodySHA256(c) {
		t.Fatal("authentication-state text must remain part of normalized identity")
	}
}
