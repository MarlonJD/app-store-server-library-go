package appstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

var (
	appleReceiptSigningOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	appleWWDROID           = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
)

type SignedDataVerifierOptions struct {
	RootCertificates [][]byte
	BundleID         string
	AppAppleID       int64
	Environment      Environment
	Now              func() time.Time
}

type SignedDataVerifier struct {
	roots       *x509.CertPool
	rootCerts   []*x509.Certificate
	bundleID    string
	appAppleID  int64
	environment Environment
	now         func() time.Time
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
	return &SignedDataVerifier{
		roots:       roots,
		rootCerts:   rootCerts,
		bundleID:    opts.BundleID,
		appAppleID:  opts.AppAppleID,
		environment: opts.Environment,
		now:         opts.Now,
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
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   effectiveDate.UTC(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return verificationError(InvalidCertificate, err)
	}
	return nil
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
