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
	"math/big"
	"strings"
	"testing"
	"time"
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

func testVerifier(t *testing.T, rootDER []byte, now time.Time) *SignedDataVerifier {
	t.Helper()
	verifier, err := NewSignedDataVerifier(SignedDataVerifierOptions{
		RootCertificates: [][]byte{rootDER},
		BundleID:         "com.example.app",
		Environment:      EnvironmentSandbox,
		Now:              func() time.Time { return now },
	})
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
	rootDER         []byte
	intermediateDER []byte
	leafDER         []byte
	leafKey         *ecdsa.PrivateKey
}

func (c generatedChain) x5c() []string {
	return []string{
		base64.StdEncoding.EncodeToString(c.leafDER),
		base64.StdEncoding.EncodeToString(c.intermediateDER),
		base64.StdEncoding.EncodeToString(c.rootDER),
	}
}

func testChain(t *testing.T, notBefore, notAfter time.Time) generatedChain {
	t.Helper()
	rootKey := newP256Key(t)
	intermediateKey := newP256Key(t)
	leafKey := newP256Key(t)

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
		ExtraExtensions:       []pkix.Extension{{Id: appleReceiptSigningOID, Value: []byte{0x05, 0x00}}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	return generatedChain{
		rootDER:         rootDER,
		intermediateDER: intermediateDER,
		leafDER:         leafDER,
		leafKey:         leafKey,
	}
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
