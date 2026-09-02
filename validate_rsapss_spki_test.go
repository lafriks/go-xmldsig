package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// TestSHA224DigestSupported checks that the SHA-224 reference digest URI is
// wired into the digest tables in both directions.
func TestSHA224DigestSupported(t *testing.T) {
	const sha224URI = "http://www.w3.org/2001/04/xmldsig-more#sha224"

	require.Equal(t, sha224URI, digestAlgorithmIdentifiers[crypto.SHA224])
	require.Equal(t, crypto.SHA224, digestAlgorithmsByIdentifier[sha224URI])
	require.True(t, crypto.SHA224.Available(), "crypto.SHA224 must be registered")
}

// patchSPKIToRSAPSS rewrites the SubjectPublicKeyInfo algorithm OID of a
// DER-encoded certificate from rsaEncryption (1.2.840.113549.1.1.1) to
// id-RSASSA-PSS (1.2.840.113549.1.1.10), mimicking the signer certificates
// carried by e.g. the German trusted list. Go's x509 leaves the PublicKey of
// such a certificate nil.
func patchSPKIToRSAPSS(t *testing.T, der []byte) []byte {
	t.Helper()
	rsaEncryptionOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	rsaPSSOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}

	require.Equal(t, 1, bytes.Count(der, rsaEncryptionOID),
		"expected exactly one rsaEncryption OID (the SPKI algorithm) in the certificate")

	patched := make([]byte, len(der))
	copy(patched, der)
	idx := bytes.Index(patched, rsaEncryptionOID)
	copy(patched[idx:], rsaPSSOID)
	return patched
}

// TestNormalizeCertRSAPSSSPKI covers the helper in isolation: a certificate
// whose SPKI names id-RSASSA-PSS parses with a nil PublicKey, and normalizeCert
// recovers the RSA key and marks the algorithm as RSA.
func TestNormalizeCertRSAPSSSPKI(t *testing.T) {
	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)

	patched := patchSPKIToRSAPSS(t, ks.cert)
	cert, err := x509.ParseCertificate(patched)
	require.NoError(t, err)
	require.Nil(t, cert.PublicKey, "Go's x509 should leave an id-RSASSA-PSS key unparsed")

	normalizeCert(cert)

	require.Equal(t, x509.RSA, cert.PublicKeyAlgorithm)
	require.NotNil(t, cert.PublicKey)
	require.True(t, ks.privateKey.PublicKey.Equal(cert.PublicKey))
}

// TestValidateWithRSAPSSSPKICert is the end-to-end proof: a document signed by
// a key whose certificate carries an id-RSASSA-PSS SPKI validates through the
// normal (non-PSS) signature path, which previously failed with an
// "algorithm unimplemented" error because cert.PublicKey was nil.
func TestValidateWithRSAPSSSPKICert(t *testing.T) {
	el := etree.NewElement("Root")
	el.CreateAttr("ID", "root-id")
	el.CreateElement("Child").SetText("payload")

	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	sctx := NewDefaultSigningContext(ks)
	signed, err := sctx.SignEnveloped(el)
	require.NoError(t, err)

	// Swap the embedded KeyInfo certificate and the trust anchor for a version
	// whose SPKI names id-RSASSA-PSS (leaving the RSA key material intact).
	patched := patchSPKIToRSAPSS(t, ks.cert)
	patchedCert, err := x509.ParseCertificate(patched)
	require.NoError(t, err)
	require.Nil(t, patchedCert.PublicKey)

	certEl := signed.FindElement("//X509Certificate")
	require.NotNil(t, certEl)
	certEl.SetText(base64.StdEncoding.EncodeToString(patched))

	vctx := NewDefaultValidationContext(&MemoryX509CertificateStore{Roots: []*x509.Certificate{patchedCert}})

	_, err = vctx.Validate(signed)
	require.NoError(t, err)

	// Tampering with the signed content must still fail.
	tampered := signed.Copy()
	tampered.FindElement("//Child").SetText("tampered")
	_, err = vctx.Validate(tampered)
	require.Error(t, err)
}
