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

// signPSSWithMutatedParams produces a valid enveloped RSA-PSS (SHA-256)
// signature after mutate has altered the RSAPSSParams element. Because the
// signature is recomputed over the mutated (and therefore self-consistent)
// SignedInfo, any rejection during validation comes from the parameter checks
// rather than from a broken signature.
func signPSSWithMutatedParams(t *testing.T, mutate func(params *etree.Element)) (*etree.Element, *MemoryX509CertificateStore) {
	t.Helper()

	el := etree.NewElement("Root")
	el.CreateAttr("ID", "root-id")
	el.CreateElement("Child").SetText("payload")

	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	sctx := NewDefaultSigningContext(ks)
	require.NoError(t, sctx.SetPSSSignatureMethod(crypto.SHA256))

	signed, err := sctx.SignEnveloped(el)
	require.NoError(t, err)

	params := signed.FindElement("//" + SignatureMethodTag + "/RSAPSSParams")
	require.NotNil(t, params)
	mutate(params)

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
	return signed, &MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
}

// TestValidatePSSUnsupportedMGFAndTrailer verifies that RSA-PSS parameters Go's
// rsa.VerifyPSS cannot honor — an MGF1 hash that differs from the digest hash,
// an unrecognized mask generation function, or a non-standard trailer field —
// are rejected explicitly instead of being silently ignored (which previously
// let a signature declaring parameters it did not actually use validate).
func TestValidatePSSUnsupportedMGFAndTrailer(t *testing.T) {
	t.Run("mgf hash differs from digest hash", func(t *testing.T) {
		signed, store := signPSSWithMutatedParams(t, func(params *etree.Element) {
			mgfDigest := params.FindElement("MaskGenerationFunction/DigestMethod")
			require.NotNil(t, mgfDigest)
			mgfDigest.CreateAttr(AlgorithmAttr, "http://www.w3.org/2001/04/xmlenc#sha512")
		})
		_, err := NewDefaultValidationContext(store).Validate(signed)
		require.ErrorContains(t, err, "mask generation function hash")
	})

	t.Run("unsupported mgf algorithm", func(t *testing.T) {
		signed, store := signPSSWithMutatedParams(t, func(params *etree.Element) {
			mgf := params.FindElement("MaskGenerationFunction")
			require.NotNil(t, mgf)
			mgf.CreateAttr(AlgorithmAttr, "http://example.com/unknown#MGF2")
		})
		_, err := NewDefaultValidationContext(store).Validate(signed)
		require.ErrorContains(t, err, "unsupported mask generation function")
	})

	t.Run("non-standard trailer field", func(t *testing.T) {
		signed, store := signPSSWithMutatedParams(t, func(params *etree.Element) {
			trailer := params.FindElement("TrailerField")
			require.NotNil(t, trailer)
			trailer.SetText("2")
		})
		_, err := NewDefaultValidationContext(store).Validate(signed)
		require.ErrorContains(t, err, "trailer field")
	})
}
