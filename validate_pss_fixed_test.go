package xmldsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"

	"github.com/lafriks/go-xmldsig/v2/etreeutils"
)

// TestValidateFixedParameterRSAPSS covers the RFC 6931 fixed-parameter
// RSASSA-PSS signature methods (§2.3.6–2.3.10, e.g.
// xmldsig-more#sha256-rsa-MGF1): the hash is implied by the URI, MGF1 uses
// the same hash, the salt length equals the hash length and no RSAPSSParams
// element is present. Several EU trusted lists (Germany's, for one) sign
// this way. The fixture is built by signing with the library, rewriting the
// SignatureMethod to the fixed URI, and re-signing the canonical SignedInfo
// with RSASSA-PSS.
func TestValidateFixedParameterRSAPSS(t *testing.T) {
	el := etree.NewElement("Root")
	el.CreateAttr("ID", "root-id")
	el.CreateElement("Child").SetText("payload")

	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	sctx := NewDefaultSigningContext(ks)
	signed, err := sctx.SignEnveloped(el)
	require.NoError(t, err)

	// Rewrite to the fixed-parameter PSS method.
	smEl := signed.FindElement("//SignatureMethod")
	require.NotNil(t, smEl)
	smEl.CreateAttr(AlgorithmAttr, "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1")

	// Compute the canonical SignedInfo bytes exactly as validation will.
	work := signed.Copy()
	sigEl := work.FindElement("//Signature")
	require.NotNil(t, sigEl)
	_, _, err = prepareSignature(etreeutils.NewDefaultNSContext(), sigEl, DefaultIDAttr)
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
	svEl := signed.FindElement("//SignatureValue")
	require.NotNil(t, svEl)
	svEl.SetText(base64.StdEncoding.EncodeToString(sigVal))

	cert, err := x509.ParseCertificate(ks.cert)
	require.NoError(t, err)
	vctx := NewDefaultValidationContext(&MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})

	_, err = vctx.Validate(signed)
	require.NoError(t, err)

	// Tampering with the signed content must still fail.
	tampered := signed.Copy()
	tampered.FindElement("//Child").SetText("tampered")
	_, err = vctx.Validate(tampered)
	require.Error(t, err)
}

// TestRSAPublicKeyFromPSSSPKI covers extracting an RSA public key from a
// SubjectPublicKeyInfo that names id-RSASSA-PSS (RFC 4055) — Go's x509
// leaves such keys unparsed (PublicKey == nil) even though the key material
// is a plain RSAPublicKey. Germany's trusted-list signer certificates carry
// this shape.
func TestRSAPublicKeyFromPSSSPKI(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	makeSPKI := func(oid asn1.ObjectIdentifier) []byte {
		spki := struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
			PublicKey: asn1.BitString{Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)},
		}
		spki.PublicKey.BitLength = len(spki.PublicKey.Bytes) * 8
		raw, err := asn1.Marshal(spki)
		require.NoError(t, err)
		return raw
	}

	pub, err := rsaPublicKeyFromPSSSPKI(makeSPKI(oidPublicKeyRSAPSS))
	require.NoError(t, err)
	require.True(t, pub.Equal(&key.PublicKey))

	// An rsaEncryption SPKI is not this function's business.
	oidRSAEncryption := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	_, err = rsaPublicKeyFromPSSSPKI(makeSPKI(oidRSAEncryption))
	require.Error(t, err)
}
