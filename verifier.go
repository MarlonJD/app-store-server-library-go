package appstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	appleReceiptSigningOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	appleWWDROID           = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
)

const (
	onlineCheckCacheLimit = 32
	onlineCheckCacheTTL   = 15 * time.Minute
	ocspMaxClockSkew      = time.Minute
	maxOCSPResponseBytes  = 1024 * 1024
)

type SignedDataVerifierOptions struct {
	RootCertificates   [][]byte
	BundleID           string
	AppAppleID         int64
	Environment        Environment
	EnableOnlineChecks bool
	HTTPClient         *http.Client
	Now                func() time.Time
}

type SignedDataVerifier struct {
	roots              *x509.CertPool
	rootCerts          []*x509.Certificate
	bundleID           string
	appAppleID         int64
	environment        Environment
	enableOnlineChecks bool
	httpClient         *http.Client
	now                func() time.Time
	cacheMu            sync.Mutex
	chainCache         map[string]time.Time
}

func NewSignedDataVerifier(opts SignedDataVerifierOptions) (*SignedDataVerifier, error) {
	rootDERs := opts.RootCertificates
	if len(rootDERs) == 0 {
		rootDERs = DefaultAppleRootCertificates()
	}
	roots := x509.NewCertPool()
	rootCerts := make([]*x509.Certificate, 0, len(rootDERs))
	for _, der := range rootDERs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, verificationError(InvalidCertificate, err)
		}
		roots.AddCert(cert)
		rootCerts = append(rootCerts, cert)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &SignedDataVerifier{
		roots:              roots,
		rootCerts:          rootCerts,
		bundleID:           opts.BundleID,
		appAppleID:         opts.AppAppleID,
		environment:        opts.Environment,
		enableOnlineChecks: opts.EnableOnlineChecks,
		httpClient:         httpClient,
		now:                opts.Now,
		chainCache:         map[string]time.Time{},
	}, nil
}

func (v *SignedDataVerifier) VerifyAndDecodeTransaction(signedTransactionInfo string) (JWSTransactionDecodedPayload, error) {
	payload, err := verifyJWT[JWSTransactionDecodedPayload](v, signedTransactionInfo, func(p JWSTransactionDecodedPayload) time.Time {
		return millisToTime(p.SignedDate)
	})
	if err != nil {
		return JWSTransactionDecodedPayload{}, err
	}
	if err := v.verifyApp(payload.BundleID, 0, payload.Environment); err != nil {
		return JWSTransactionDecodedPayload{}, err
	}
	return payload, nil
}

func (v *SignedDataVerifier) VerifyAndDecodeRenewalInfo(signedRenewalInfo string) (JWSRenewalInfoDecodedPayload, error) {
	payload, err := verifyJWT[JWSRenewalInfoDecodedPayload](v, signedRenewalInfo, func(p JWSRenewalInfoDecodedPayload) time.Time {
		return millisToTime(p.SignedDate)
	})
	if err != nil {
		return JWSRenewalInfoDecodedPayload{}, err
	}
	if v.environment != "" && payload.Environment != v.environment {
		return JWSRenewalInfoDecodedPayload{}, verificationError(InvalidEnvironment, nil)
	}
	return payload, nil
}

func (v *SignedDataVerifier) VerifyAndDecodeAppTransaction(signedAppTransaction string) (JWSAppTransactionDecodedPayload, error) {
	payload, err := verifyJWT[JWSAppTransactionDecodedPayload](v, signedAppTransaction, func(p JWSAppTransactionDecodedPayload) time.Time {
		return millisToTime(p.ReceiptCreationDate)
	})
	if err != nil {
		return JWSAppTransactionDecodedPayload{}, err
	}
	if err := v.verifyApp(payload.BundleID, payload.AppAppleID, payload.ReceiptType); err != nil {
		return JWSAppTransactionDecodedPayload{}, err
	}
	return payload, nil
}

func (v *SignedDataVerifier) VerifyAndDecodeNotification(signedPayload string) (ResponseBodyV2DecodedPayload, error) {
	payload, err := verifyJWT[ResponseBodyV2DecodedPayload](v, signedPayload, func(p ResponseBodyV2DecodedPayload) time.Time {
		return millisToTime(p.SignedDate)
	})
	if err != nil {
		return ResponseBodyV2DecodedPayload{}, err
	}
	bundleID, appAppleID, environment := notificationAppFields(payload)
	if err := v.verifyApp(bundleID, appAppleID, environment); err != nil {
		return ResponseBodyV2DecodedPayload{}, err
	}
	return payload, nil
}

func notificationAppFields(payload ResponseBodyV2DecodedPayload) (string, int64, Environment) {
	if payload.Data != nil {
		return payload.Data.BundleID, payload.Data.AppAppleID, payload.Data.Environment
	}
	if payload.Summary != nil {
		return payload.Summary.BundleID, payload.Summary.AppAppleID, payload.Summary.Environment
	}
	if payload.ExternalPurchaseToken != nil {
		env := EnvironmentProduction
		if strings.HasPrefix(payload.ExternalPurchaseToken.ExternalPurchaseID, "SANDBOX") {
			env = EnvironmentSandbox
		}
		return payload.ExternalPurchaseToken.BundleID, payload.ExternalPurchaseToken.AppAppleID, env
	}
	return "", 0, ""
}

func (v *SignedDataVerifier) verifyApp(bundleID string, appAppleID int64, environment Environment) error {
	if v.bundleID != "" && bundleID != v.bundleID {
		return verificationError(InvalidAppIdentifier, nil)
	}
	if v.environment == EnvironmentProduction && v.appAppleID != 0 && appAppleID != 0 && appAppleID != v.appAppleID {
		return verificationError(InvalidAppIdentifier, nil)
	}
	if v.environment != "" && environment != "" && environment != v.environment {
		return verificationError(InvalidEnvironment, nil)
	}
	return nil
}

func verifyJWT[T any](v *SignedDataVerifier, jws string, signedDate func(T) time.Time) (T, error) {
	var zero T
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return zero, verificationError(InvalidSignedData, errors.New("compact JWS must have three parts"))
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return zero, verificationError(InvalidSignedData, err)
	}
	var header JWSDecodedHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return zero, verificationError(InvalidSignedData, err)
	}
	if header.Alg != "ES256" {
		return zero, verificationError(VerificationFailure, errors.New("JWS alg must be ES256"))
	}
	if len(header.X5C) != 3 {
		return zero, verificationError(InvalidChainLength, nil)
	}
	chain, err := parseX5C(header.X5C)
	if err != nil {
		return zero, verificationError(InvalidCertificate, err)
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, verificationError(InvalidSignedData, err)
	}
	var payload T
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return zero, verificationError(InvalidSignedData, err)
	}
	effectiveDate := signedDate(payload)
	if effectiveDate.IsZero() {
		effectiveDate = v.now().UTC()
	}
	if err := v.verifyCertificateChain(chain[0], chain[1], chain[2], effectiveDate); err != nil {
		return zero, err
	}
	if err := verifyES256(parts[0]+"."+parts[1], parts[2], chain[0]); err != nil {
		return zero, verificationError(VerificationFailure, err)
	}
	return payload, nil
}

func parseX5C(encoded []string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(encoded))
	for _, entry := range encoded {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (v *SignedDataVerifier) verifyCertificateChain(leaf, intermediate, root *x509.Certificate, effectiveDate time.Time) error {
	now := v.now().UTC()
	if v.enableOnlineChecks && v.isChainCached(leaf, intermediate, root, now) {
		return nil
	}
	if !v.isTrustedRoot(root) {
		return verificationError(InvalidCertificate, errors.New("x5c root is not trusted"))
	}
	if !hasExtension(leaf, appleReceiptSigningOID) {
		return verificationError(InvalidCertificate, errors.New("leaf certificate missing Apple receipt signing extension"))
	}
	if !hasExtension(intermediate, appleWWDROID) {
		return verificationError(InvalidCertificate, errors.New("intermediate certificate missing Apple WWDR extension"))
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	verificationTime := effectiveDate.UTC()
	if v.enableOnlineChecks {
		verificationTime = now
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   verificationTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return verificationError(InvalidCertificate, err)
	}
	if v.enableOnlineChecks {
		if err := v.checkOCSPStatus(leaf, intermediate, now); err != nil {
			return err
		}
		if err := v.checkOCSPStatus(intermediate, root, now); err != nil {
			return err
		}
		v.cacheChain(leaf, intermediate, root, now.Add(onlineCheckCacheTTL))
	}
	return nil
}

func (v *SignedDataVerifier) checkOCSPStatus(cert, issuer *x509.Certificate, now time.Time) error {
	if len(cert.OCSPServer) == 0 {
		return verificationError(InvalidCertificate, errors.New("certificate has no OCSP server"))
	}
	request, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return verificationError(InvalidCertificate, err)
	}
	req, err := http.NewRequest(http.MethodPost, cert.OCSPServer[0], bytes.NewReader(request))
	if err != nil {
		return verificationError(InvalidCertificate, err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")

	res, err := v.httpClient.Do(req)
	if err != nil {
		return verificationError(RetryableVerificationFailure, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return verificationError(RetryableVerificationFailure, fmt.Errorf("ocsp responder status %d", res.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxOCSPResponseBytes+1))
	if err != nil {
		return verificationError(RetryableVerificationFailure, err)
	}
	if len(raw) > maxOCSPResponseBytes {
		return verificationError(RetryableVerificationFailure, errors.New("ocsp response too large"))
	}
	response, err := ocsp.ParseResponseForCert(raw, cert, issuer)
	if err != nil {
		return verificationError(VerificationFailure, err)
	}
	switch response.Status {
	case ocsp.Good:
	case ocsp.Revoked:
		return verificationError(InvalidCertificate, errors.New("certificate is revoked"))
	case ocsp.Unknown:
		return verificationError(VerificationFailure, errors.New("ocsp responder returned unknown certificate status"))
	default:
		return verificationError(VerificationFailure, fmt.Errorf("unknown ocsp certificate status %d", response.Status))
	}
	if response.ThisUpdate.After(now.Add(ocspMaxClockSkew)) {
		return verificationError(VerificationFailure, errors.New("ocsp thisUpdate is in the future"))
	}
	if !response.NextUpdate.IsZero() && response.NextUpdate.Before(now.Add(-ocspMaxClockSkew)) {
		return verificationError(RetryableVerificationFailure, errors.New("ocsp response is expired"))
	}
	return nil
}

func (v *SignedDataVerifier) isChainCached(leaf, intermediate, root *x509.Certificate, now time.Time) bool {
	key := certificateChainCacheKey(leaf, intermediate, root)
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	expiresAt, ok := v.chainCache[key]
	if !ok {
		return false
	}
	if !expiresAt.After(now) {
		delete(v.chainCache, key)
		return false
	}
	return true
}

func (v *SignedDataVerifier) cacheChain(leaf, intermediate, root *x509.Certificate, expiresAt time.Time) {
	key := certificateChainCacheKey(leaf, intermediate, root)
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	if len(v.chainCache) >= onlineCheckCacheLimit {
		for cachedKey, expiry := range v.chainCache {
			if expiry.Before(v.now().UTC()) {
				delete(v.chainCache, cachedKey)
			}
		}
	}
	if len(v.chainCache) >= onlineCheckCacheLimit {
		for cachedKey := range v.chainCache {
			delete(v.chainCache, cachedKey)
			break
		}
	}
	v.chainCache[key] = expiresAt
}

func certificateChainCacheKey(leaf, intermediate, root *x509.Certificate) string {
	sum := sha256.New()
	sum.Write(leaf.Raw)
	sum.Write(intermediate.Raw)
	sum.Write(root.Raw)
	return string(sum.Sum(nil))
}

func (v *SignedDataVerifier) isTrustedRoot(root *x509.Certificate) bool {
	for _, trusted := range v.rootCerts {
		if bytes.Equal(root.Raw, trusted.Raw) {
			return true
		}
	}
	return false
}

func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func verifyES256(signingInput, encodedSignature string, leaf *x509.Certificate) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("leaf public key is not ECDSA")
	}
	sig, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != size*2 {
		return errors.New("invalid ES256 signature length")
	}
	sum := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return errors.New("JWS signature verification failed")
	}
	return nil
}

func millisToTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}
