package xmldsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"

	"github.com/lafriks/go-xmldsig/v2/etreeutils"
)

// signPSSWithDeclaredSalt produces an enveloped RSA-PSS signature whose
// RSAPSSParams/SaltLength declares declaredSalt but whose SignatureValue is
// actually computed with actualSalt bytes of salt. When the two differ the
// signature is self-inconsistent: a verifier that honors the declared length
// must reject it, while one using PSSSaltLengthAuto would accept it.
func signPSSWithDeclaredSalt(t *testing.T, declaredSalt, actualSalt int) (*etree.Element, *MemoryX509CertificateStore) {
	t.Helper()

	el := etree.NewElement("Root")
	el.CreateAttr("ID", "root-id")
	el.CreateElement("Child").SetText("payload")

	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	sctx := NewDefaultSigningContext(ks)
	require.NoError(t, sctx.SetPSSSignatureMethod(crypto.SHA256))

	signed, err := sctx.SignEnveloped(el)
	require.NoError(t, err)

	// Declare the chosen salt length in the signed RSAPSSParams.
	saltEl := signed.FindElement("//" + SignatureMethodTag + "/RSAPSSParams/SaltLength")
	require.NotNil(t, saltEl)
	saltEl.SetText(strconv.Itoa(declaredSalt))

	// Recompute the canonical SignedInfo (now carrying the edited SaltLength)
	// exactly as validation will, and sign it with actualSalt bytes of salt.
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
		SaltLength: actualSalt,
	})
	require.NoError(t, err)

	svEl := signed.FindElement("//" + SignatureValueTag)
	require.NotNil(t, svEl)
	svEl.SetText(base64.StdEncoding.EncodeToString(sigVal))

	cert, err := x509.ParseCertificate(ks.cert)
	require.NoError(t, err)
	return signed, &MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
}

// TestValidatePSSDeclaredSaltLengthEnforced verifies that a declared
// RSAPSSParams/SaltLength is enforced: a signature whose actual salt matches
// the declared length validates, while one whose actual salt differs is
// rejected (with PSSSaltLengthAuto it would have been accepted).
func TestValidatePSSDeclaredSaltLengthEnforced(t *testing.T) {
	t.Run("matching salt validates", func(t *testing.T) {
		signed, store := signPSSWithDeclaredSalt(t, 20, 20)
		vctx := NewDefaultValidationContext(store)
		_, err := vctx.Validate(signed)
		require.NoError(t, err)
	})

	t.Run("mismatched salt is rejected", func(t *testing.T) {
		signed, store := signPSSWithDeclaredSalt(t, 48, 20)
		vctx := NewDefaultValidationContext(store)
		_, err := vctx.Validate(signed)
		require.Error(t, err)
	})
}
