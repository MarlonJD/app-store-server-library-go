# Golden Test Fixtures

`verifier_test.go` contains a golden test for a real Apple Sandbox
`signedTransactionInfo` JWS. The test is skipped until this fixture exists:

```text
testdata/apple_sandbox_signed_transaction_info.jws
```

Use a disposable Sandbox app/account transaction and make sure the payload does
not expose production user data. The fixture should contain the compact JWS
string only.
