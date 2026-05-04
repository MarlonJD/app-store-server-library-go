package appstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestSignedDataVerifierAcceptsValidAppleLikeChain(t *testing.T) {
	fixed := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	chain := testChain(t, fixed.Add(-time.Hour), fixed.Add(time.Hour))
	verifier := testVerifier(t, chain.rootDER, fixed)
	payload := testTransactionPayload(fixed)

	got, err := verifier.VerifyAndDecodeTransaction(signJWS(t, chain.x5c(), payload, chain.leafKey, "ES256"))
	if err != nil {
		t.Fatalf("verify transaction: %v", err)
	}
	if got.ProductID != "com.example.premium" || got.BundleID != "com.example.app" {
		t.Fatalf("decoded payload = %+v", got)
	}
}

func TestSignedDataVerifierRejectsInvalidInputs(t *testing.T) {
	fixed := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	chain := testChain(t, fixed.Add(-time.Hour), fixed.Add(time.Hour))
	verifier := testVerifier(t, chain.rootDER, fixed)
	validPayload := testTransactionPayload(fixed)
	valid := signJWS(t, chain.x5c(), validPayload, chain.leafKey, "ES256")

	expiredChain := testChain(t, fixed.Add(-2*time.Hour), fixed.Add(-time.Hour))
	selfSigned := testSelfSignedJWS(t, validPayload, fixed)

	cases := []struct {
		name string
		jws  string
	}{
		{
			name: "self signed",
			jws:  selfSigned,
		},
		{
			name: "tampered payload",
			jws:  tamperPayload(t, valid, map[string]any{"productId": "evil"}),
		},
		{
			name: "tampered signature",
			jws:  valid[:len(valid)-2] + "xx",
		},
		{
			name: "wrong alg",
			jws:  signJWS(t, chain.x5c(), validPayload, chain.leafKey, "HS256"),
		},
		{
			name: "missing x5c",
			jws:  signJWSWithHeader(t, map[string]any{"alg": "ES256"}, validPayload, chain.leafKey),
		},
		{
			name: "expired cert",
			jws:  signJWS(t, expiredChain.x5c(), validPayload, expiredChain.leafKey, "ES256"),
		},
		{
			name: "wrong bundle",
			jws: signJWS(t, chain.x5c(), map[string]any{
				"transactionId":         "tx-1",
				"originalTransactionId": "orig-1",
				"bundleId":              "com.other.app",
				"productId":             "com.example.premium",
				"expiresDate":           fixed.Add(time.Hour).UnixMilli(),
				"signedDate":            fixed.UnixMilli(),
				"environment":           "Sandbox",
			}, chain.leafKey, "ES256"),
		},
		{
			name: "wrong environment",
			jws: signJWS(t, chain.x5c(), map[string]any{
				"transactionId":         "tx-1",
				"originalTransactionId": "orig-1",
				"bundleId":              "com.example.app",
				"productId":             "com.example.premium",
				"expiresDate":           fixed.Add(time.Hour).UnixMilli(),
				"signedDate":            fixed.UnixMilli(),
				"environment":           "Production",
			}, chain.leafKey, "ES256"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.VerifyAndDecodeTransaction(tc.jws); err == nil {
				t.Fatal("expected verification error")
			}
		})
	}
}

func TestSignedDataVerifierOnlineChecksAcceptsGoodOCSPAndCaches(t *testing.T) {
	fixed := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	var requestCount atomic.Int64
	var chain generatedChain
	server := testOCSPServer(t, fixed, &chain, func(cert *x509.Certificate) int {
		requestCount.Add(1)
		return ocsp.Good
	})
	defer server.Close()
	chain = testChain(t, fixed.Add(-time.Hour), fixed.Add(time.Hour), server.URL)
	verifier := testVerifierWithOptions(t, SignedDataVerifierOptions{
		RootCertificates:   [][]byte{chain.rootDER},
		BundleID:           "com.example.app",
		Environment:        EnvironmentSandbox,
		EnableOnlineChecks: true,
		Now:                func() time.Time { return fixed },
	})
	signed := signJWS(t, chain.x5c(), testTransactionPayload(fixed), chain.leafKey, "ES256")

	for i := 0; i < 2; i++ {
		got, err := verifier.VerifyAndDecodeTransaction(signed)
		if err != nil {
			t.Fatalf("verify transaction: %v", err)
		}
		if got.TransactionID != "tx-1" {
			t.Fatalf("transaction id = %q", got.TransactionID)
		}
	}
	if got := requestCount.Load(); got != 2 {
		t.Fatalf("ocsp requests = %d, want 2 for one leaf and one intermediate check", got)
	}
}

func TestSignedDataVerifierOnlineChecksRejectsRevokedOCSP(t *testing.T) {
	fixed := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	var chain generatedChain
	server := testOCSPServer(t, fixed, &chain, func(cert *x509.Certificate) int {
		if cert.SerialNumber.Cmp(chain.leafCert.SerialNumber) == 0 {
			return ocsp.Revoked
		}
		return ocsp.Good
	})
	defer server.Close()
	chain = testChain(t, fixed.Add(-time.Hour), fixed.Add(time.Hour), server.URL)
	verifier := testVerifierWithOptions(t, SignedDataVerifierOptions{
		RootCertificates:   [][]byte{chain.rootDER},
		BundleID:           "com.example.app",
		Environment:        EnvironmentSandbox,
		EnableOnlineChecks: true,
		Now:                func() time.Time { return fixed },
	})

	_, err := verifier.VerifyAndDecodeTransaction(signJWS(t, chain.x5c(), testTransactionPayload(fixed), chain.leafKey, "ES256"))
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Status != InvalidCertificate {
		t.Fatalf("error = %#v, want InvalidCertificate", err)
	}
}

func TestSignedDataVerifierOnlineChecksTreatsOCSPResponderErrorsAsRetryable(t *testing.T) {
	fixed := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	chain := testChain(t, fixed.Add(-time.Hour), fixed.Add(time.Hour), server.URL)
	verifier := testVerifierWithOptions(t, SignedDataVerifierOptions{
		RootCertificates:   [][]byte{chain.rootDER},
		BundleID:           "com.example.app",
		Environment:        EnvironmentSandbox,
		EnableOnlineChecks: true,
		Now:                func() time.Time { return fixed },
	})

	_, err := verifier.VerifyAndDecodeTransaction(signJWS(t, chain.x5c(), testTransactionPayload(fixed), chain.leafKey, "ES256"))
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Status != RetryableVerificationFailure {
		t.Fatalf("error = %#v, want RetryableVerificationFailure", err)
	}
}

func TestSignedDataVerifierOnlineChecksUseCurrentDateForCertificateValidity(t *testing.T) {
	signedAt := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	now := signedAt.Add(2 * time.Hour)
	chain := testChain(t, signedAt.Add(-time.Hour), signedAt.Add(time.Hour))
	signed := signJWS(t, chain.x5c(), testTransactionPayload(signedAt), chain.leafKey, "ES256")

	offline := testVerifierWithOptions(t, SignedDataVerifierOptions{
		RootCertificates: [][]byte{chain.rootDER},
		BundleID:         "com.example.app",
		Environment:      EnvironmentSandbox,
		Now:              func() time.Time { return now },
	})
	if _, err := offline.VerifyAndDecodeTransaction(signed); err != nil {
		t.Fatalf("offline verification should use signedDate: %v", err)
	}

	online := testVerifierWithOptions(t, SignedDataVerifierOptions{
		RootCertificates:   [][]byte{chain.rootDER},
		BundleID:           "com.example.app",
		Environment:        EnvironmentSandbox,
		EnableOnlineChecks: true,
		Now:                func() time.Time { return now },
	})
	_, err := online.VerifyAndDecodeTransaction(signed)
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Status != InvalidCertificate {
		t.Fatalf("error = %#v, want InvalidCertificate", err)
	}
}

func TestSignedDataVerifierAppleSandboxGoldenTransaction(t *testing.T) {
	path := filepath.Join("testdata", "apple_sandbox_signed_transaction_info.jws")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("add a real Apple Sandbox signedTransactionInfo fixture at testdata/apple_sandbox_signed_transaction_info.jws")
	}
	if err != nil {
		t.Fatal(err)
	}
	signed := strings.TrimSpace(string(raw))
	if signed == "" {
		t.Skip("testdata/apple_sandbox_signed_transaction_info.jws is empty")
	}
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("golden fixture is not a compact JWS")
	}
	var payload JWSTransactionDecodedPayload
	if err := decodeJWTSegment(parts[1], &payload); err != nil {
		t.Fatalf("decode golden payload: %v", err)
	}
	if payload.BundleID == "" {
		t.Fatalf("golden payload is missing bundleId")
	}
	verifier, err := NewSignedDataVerifier(SignedDataVerifierOptions{
		BundleID:    payload.BundleID,
		Environment: EnvironmentSandbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier.VerifyAndDecodeTransaction(signed)
	if err != nil {
		t.Fatalf("verify Apple Sandbox golden transaction: %v", err)
	}
	if got.Environment != EnvironmentSandbox {
		t.Fatalf("environment = %q, want Sandbox", got.Environment)
	}
	if got.BundleID != payload.BundleID {
		t.Fatalf("bundle id = %q, want %q", got.BundleID, payload.BundleID)
	}
}

func testVerifier(t *testing.T, rootDER []byte, now time.Time) *SignedDataVerifier {
	t.Helper()
	return testVerifierWithOptions(t, SignedDataVerifierOptions{
		RootCertificates: [][]byte{rootDER},
		BundleID:         "com.example.app",
		Environment:      EnvironmentSandbox,
		Now:              func() time.Time { return now },
	})
}

func testVerifierWithOptions(t *testing.T, opts SignedDataVerifierOptions) *SignedDataVerifier {
	t.Helper()
	verifier, err := NewSignedDataVerifier(opts)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func testTransactionPayload(now time.Time) map[string]any {
	return map[string]any{
		"transactionId":         "tx-1",
		"originalTransactionId": "orig-1",
		"bundleId":              "com.example.app",
		"productId":             "com.example.premium",
		"expiresDate":           now.Add(time.Hour).UnixMilli(),
		"signedDate":            now.UnixMilli(),
		"environment":           "Sandbox",
		"appAccountToken":       "018f8c8a-0001-7000-9000-000000000001",
	}
}

type generatedChain struct {
	rootDER          []byte
	intermediateDER  []byte
	leafDER          []byte
	rootCert         *x509.Certificate
	intermediateCert *x509.Certificate
	leafCert         *x509.Certificate
	rootKey          *ecdsa.PrivateKey
	intermediateKey  *ecdsa.PrivateKey
	leafKey          *ecdsa.PrivateKey
}

func (c generatedChain) x5c() []string {
	return []string{
		base64.StdEncoding.EncodeToString(c.leafDER),
		base64.StdEncoding.EncodeToString(c.intermediateDER),
		base64.StdEncoding.EncodeToString(c.rootDER),
	}
}

func testChain(t *testing.T, notBefore, notAfter time.Time, ocspServerURL ...string) generatedChain {
	t.Helper()
	rootKey := newP256Key(t)
	intermediateKey := newP256Key(t)
	leafKey := newP256Key(t)
	var ocspServers []string
	if len(ocspServerURL) > 0 && ocspServerURL[0] != "" {
		ocspServers = []string{ocspServerURL[0]}
	}

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Apple Root Test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Apple WWDR Test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		OCSPServer:            ocspServers,
		ExtraExtensions:       []pkix.Extension{{Id: appleWWDROID, Value: []byte{0x05, 0x00}}},
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "App Store Receipt Signing Test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		OCSPServer:            ocspServers,
		ExtraExtensions:       []pkix.Extension{{Id: appleReceiptSigningOID, Value: []byte{0x05, 0x00}}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return generatedChain{
		rootDER:          rootDER,
		intermediateDER:  intermediateDER,
		leafDER:          leafDER,
		rootCert:         rootCert,
		intermediateCert: intermediateCert,
		leafCert:         leafCert,
		rootKey:          rootKey,
		intermediateKey:  intermediateKey,
		leafKey:          leafKey,
	}
}

func testOCSPServer(t *testing.T, now time.Time, chain *generatedChain, status func(*x509.Certificate) int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("ocsp method = %s, want POST", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read ocsp request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		request, err := ocsp.ParseRequest(raw)
		if err != nil {
			t.Errorf("parse ocsp request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cert, issuer, responder, signer := chain.ocspMaterial(request.SerialNumber)
		if cert == nil {
			t.Errorf("unexpected ocsp serial: %s", request.SerialNumber)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := ocsp.CreateResponse(issuer, responder, ocsp.Response{
			Status:             status(cert),
			SerialNumber:       cert.SerialNumber,
			ThisUpdate:         now.Add(-time.Minute),
			NextUpdate:         now.Add(time.Hour),
			RevokedAt:          now.Add(-time.Minute),
			SignatureAlgorithm: x509.ECDSAWithSHA256,
		}, signer)
		if err != nil {
			t.Errorf("create ocsp response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	}))
}

func (c generatedChain) ocspMaterial(serial *big.Int) (*x509.Certificate, *x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	if c.leafCert != nil && serial.Cmp(c.leafCert.SerialNumber) == 0 {
		return c.leafCert, c.intermediateCert, c.intermediateCert, c.intermediateKey
	}
	if c.intermediateCert != nil && serial.Cmp(c.intermediateCert.SerialNumber) == 0 {
		return c.intermediateCert, c.rootCert, c.rootCert, c.rootKey
	}
	return nil, nil, nil, nil
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signJWS(t *testing.T, x5c []string, payload map[string]any, key *ecdsa.PrivateKey, alg string) string {
	t.Helper()
	return signJWSWithHeader(t, map[string]any{"alg": alg, "x5c": x5c}, payload, key)
}

func signJWSWithHeader(t *testing.T, header map[string]any, payload map[string]any, key *ecdsa.PrivateKey) string {
	t.Helper()
	headerRaw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerRaw) + "." + base64.RawURLEncoding.EncodeToString(payloadRaw)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, size*2)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func tamperPayload(t *testing.T, jws string, changes map[string]any) string {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatal("invalid test jws")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	for key, value := range changes {
		payload[key] = value
	}
	reencoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(reencoded)
	return strings.Join(parts, ".")
}

func testSelfSignedJWS(t *testing.T, payload map[string]any, now time.Time) string {
	t.Helper()
	key := newP256Key(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Self Signed"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{{Id: appleReceiptSigningOID, Value: []byte{0x05, 0x00}}, {Id: appleWWDROID, Value: []byte{0x05, 0x00}}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	x5c := []string{
		base64.StdEncoding.EncodeToString(der),
		base64.StdEncoding.EncodeToString(der),
		base64.StdEncoding.EncodeToString(der),
	}
	return signJWS(t, x5c, payload, key, "ES256")
}
