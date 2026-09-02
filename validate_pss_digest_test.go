package xmldsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"

	"github.com/lafriks/go-xmldsig/v2/etreeutils"
)

// TestValidatePSSUnknownDigestRejected verifies that an RSA-PSS signature whose
// RSAPSSParams declares an unrecognized DigestMethod is rejected with a clear
// "unknown digest algorithm" error instead of being silently verified against
// the SHA-256 default. The document is re-signed so the signature is
// cryptographically valid over its (SHA-256-hashed) SignedInfo — before the
// fix such a document validated successfully despite the bogus digest URI.
func TestValidatePSSUnknownDigestRejected(t *testing.T) {
	const bogusDigestURI = "http://example.com/unknown#sha999"

	el := etree.NewElement("Root")
	el.CreateAttr("ID", "root-id")
	el.CreateElement("Child").SetText("payload")

	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	sctx := NewDefaultSigningContext(ks)
	require.NoError(t, sctx.SetPSSSignatureMethod(crypto.SHA256))

	signed, err := sctx.SignEnveloped(el)
	require.NoError(t, err)

	// Point the declared DigestMethod at an algorithm the library does not know.
	digestEl := signed.FindElement("//" + SignatureMethodTag + "/RSAPSSParams/DigestMethod")
	require.NotNil(t, digestEl)
	digestEl.CreateAttr(AlgorithmAttr, bogusDigestURI)

	// Re-sign the canonical SignedInfo (now carrying the bogus URI) with SHA-256
	// so the signature itself is valid — the rejection must come from the digest
	// check, not from a broken signature.
	work := signed.Copy()
	sigEl := work.FindElement("//" + SignatureTag)
	require.NotNil(t, sigEl)
	_, _, err = prepareSignature(etreeutils.NewDefaultNSContext(), sigEl, "root-id")
	require.NoError(t, err)
	signedInfoEl, err := etreeutils.NSFindOneChildCtx(etreeutils.NewDefaultNSContext(), sigEl, Namespace, SignedInfoTag)
	require.NoError(t, err)
	require.NotNil(t, signedInfoEl)
	canonical, err := canonicalSerialize(signedInfoEl)
	require.NoError(t, err)

	digest := sha256.Sum256(canonical)
	sigVal, err := rsa.SignPSS(rand.Reader, ks.privateKey, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	require.NoError(t, err)
	svEl := signed.FindElement("//" + SignatureValueTag)
	require.NotNil(t, svEl)
	svEl.SetText(base64.StdEncoding.EncodeToString(sigVal))

	cert, err := x509.ParseCertificate(ks.cert)
	require.NoError(t, err)
	vctx := NewDefaultValidationContext(&MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})

	_, err = vctx.Validate(signed)
	require.ErrorContains(t, err, "unknown digest algorithm")
}
