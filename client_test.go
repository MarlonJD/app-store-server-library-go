package appstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientCreatesExpectedJWTClaims(t *testing.T) {
	fixed := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	client := testClient(t, fixed, nil)
	token, err := client.CreateToken(fixed)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	var header map[string]any
	if err := decodeJWTSegment(parts[0], &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "ES256" || header["kid"] != "KEY123" || header["typ"] != "JWT" {
		t.Fatalf("header = %#v", header)
	}
	var payload map[string]any
	if err := decodeJWTSegment(parts[1], &payload); err != nil {
		t.Fatal(err)
	}
	if payload["iss"] != "issuer-1" || payload["aud"] != "appstoreconnect-v1" || payload["bid"] != "com.example.app" {
		t.Fatalf("payload = %#v", payload)
	}
	if int64(payload["iat"].(float64)) != fixed.Unix() {
		t.Fatalf("iat = %#v", payload["iat"])
	}
	if int64(payload["exp"].(float64)) != fixed.Add(20*time.Minute).Unix() {
		t.Fatalf("exp = %#v", payload["exp"])
	}
}

func TestClientRequestsAndErrors(t *testing.T) {
	fixed := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			sawAuth = true
		}
		switch r.URL.Path {
		case "/inApps/v1/transactions/tx-1":
			_, _ = w.Write([]byte(`{"signedTransactionInfo":"signed"}`))
		case "/inApps/v1/subscriptions/tx-1":
			if r.URL.Query()["status"][0] != "1" || r.URL.Query()["status"][1] != "4" {
				t.Fatalf("status query = %v", r.URL.Query()["status"])
			}
			_, _ = w.Write([]byte(`{"environment":"Sandbox","bundleId":"com.example.app","data":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorCode":4040010,"errorMessage":"not found"}`))
		}
	}))
	defer server.Close()

	client := testClient(t, fixed, &server.URL)
	info, err := client.GetTransactionInfo(context.Background(), "tx-1")
	if err != nil {
		t.Fatalf("get transaction info: %v", err)
	}
	if info.SignedTransactionInfo != "signed" || !sawAuth {
		t.Fatalf("response/auth = %+v auth:%v", info, sawAuth)
	}
	if _, err := client.GetAllSubscriptionStatuses(context.Background(), "tx-1", 1, 4); err != nil {
		t.Fatalf("subscription statuses: %v", err)
	}
	_, err = client.GetTransactionInfo(context.Background(), "missing")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound || apiErr.ErrorCode != 4040010 {
		t.Fatalf("error = %#v", err)
	}
}

func testClient(t *testing.T, now time.Time, baseURL *string) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	opts := ClientOptions{
		PrivateKeyPEM: pemKey,
		KeyID:         "KEY123",
		IssuerID:      "issuer-1",
		BundleID:      "com.example.app",
		Environment:   EnvironmentSandbox,
		Now:           func() time.Time { return now },
	}
	if baseURL != nil {
		opts.BaseURL = *baseURL
	}
	client, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func decodeJWTSegment(segment string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
