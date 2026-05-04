# App Store Server Library for Go

Go helpers for the App Store Server API and App Store Server Notifications.
The root package is `appstore`.

## Documentation

See the detailed SDK API guide in [docs/API.md](docs/API.md). It covers client
configuration, signed data verification, endpoint methods, error handling,
pagination, webhook handling, and end-to-end examples.

## Signed data verification

```go
verifier, err := appstore.NewSignedDataVerifier(appstore.SignedDataVerifierOptions{
	BundleID:           "com.example.app",
	Environment:        appstore.EnvironmentSandbox,
	EnableOnlineChecks: true,
})
if err != nil {
	panic(err)
}

tx, err := verifier.VerifyAndDecodeTransaction(signedTransactionInfo)
if err != nil {
	// Fail closed.
}
_ = tx.ProductID
```

The verifier requires `alg=ES256`, validates the `x5c` certificate chain
against Apple root certificates only, checks certificate validity at the JWS
`signedDate` by default, and rejects tampered payloads or signatures. When
`EnableOnlineChecks` is enabled, certificate validity is checked at the current
time and OCSP revocation checks are performed for the leaf and intermediate
certificates.

## API client

```go
client, err := appstore.NewClient(appstore.ClientOptions{
	PrivateKeyPEM: encodedP8Key,
	KeyID:         "ABCDEFGHIJ",
	IssuerID:      "99b16628-15e4-4668-972b-eeff55eeff55",
	BundleID:      "com.example.app",
	Environment:   appstore.EnvironmentSandbox,
})
if err != nil {
	panic(err)
}

info, err := client.GetTransactionInfo(ctx, transactionID)
```

The client signs ES256 JWTs with `alg`, `kid`, `typ`, and the `iss`, `iat`,
`exp`, `aud=appstoreconnect-v1`, `bid` claims. Production and Sandbox base
URLs are selected from the configured environment.
