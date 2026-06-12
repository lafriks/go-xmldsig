package xmldsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func makeCert(t *testing.T, cn string, isCA bool, key *rsa.PrivateKey, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, der
}

// chainSignedDoc signs a document with a leaf certificate issued by an
// intermediate CA, embedding the given DER certificates in KeyInfo, and
// returns it with a validation context whose store holds ONLY the root CA.
func chainSignedDoc(t *testing.T, keyInfoCerts func(leafDER, intermediateDER []byte) [][]byte) (*etree.Element, *ValidationContext) {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootCert, _ := makeCert(t, "Test Root CA", true, rootKey, nil, nil)
	intermediateCert, intermediateDER := makeCert(t, "Test Intermediate CA", true, intermediateKey, rootCert, rootKey)
	_, leafDER := makeCert(t, "Test Leaf", false, leafKey, intermediateCert, intermediateKey)

	doc := etree.NewElement("Document")
	doc.CreateAttr(DefaultIDAttr, "docid")
	doc.CreateElement("Payload").SetText("data")

	sctx, err := NewSigningContext(leafKey, keyInfoCerts(leafDER, intermediateDER))
	require.NoError(t, err)
	sctx.Canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := sctx.SignEnveloped(doc)
	require.NoError(t, err)

	vctx := NewDefaultValidationContext(&MemoryX509CertificateStore{
		Roots: []*x509.Certificate{rootCert},
	})
	return signed, vctx
}

// TestValidateWithRootTrustChainFromKeyInfo: a signature shipping its own
// leaf+intermediate chain in KeyInfo verifies against a store holding only
// the root CA.
func TestValidateWithRootTrustChainFromKeyInfo(t *testing.T) {
	signed, vctx := chainSignedDoc(t, func(leafDER, intermediateDER []byte) [][]byte {
		return [][]byte{leafDER, intermediateDER}
	})

	validated, err := vctx.ValidateWithRootTrust(signed)
	require.NoError(t, err,
		"intermediates carried in KeyInfo must be usable to chain the leaf to the trusted root")
	require.NotEmpty(t, validated)
}

// TestValidateWithRootTrustChainMissingIntermediate: without the intermediate
// in KeyInfo the leaf cannot chain to the root, so verification must fail.
func TestValidateWithRootTrustChainMissingIntermediate(t *testing.T) {
	signed, vctx := chainSignedDoc(t, func(leafDER, _ []byte) [][]byte {
		return [][]byte{leafDER}
	})

	_, err := vctx.ValidateWithRootTrust(signed)
	require.Error(t, err)
}

// TestValidateWithRootTrustCallerIntermediatesWin: a caller-supplied
// CertVerifyOptions.Intermediates pool is used as-is and not replaced by the
// KeyInfo certificates.
func TestValidateWithRootTrustCallerIntermediatesWin(t *testing.T) {
	signed, vctx := chainSignedDoc(t, func(leafDER, intermediateDER []byte) [][]byte {
		return [][]byte{leafDER, intermediateDER}
	})

	// An empty (but non-nil) pool: the KeyInfo intermediate must NOT be
	// consulted, so chain building fails.
	vctx.CertVerifyOptions = &x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err := vctx.ValidateWithRootTrust(signed)
	require.Error(t, err)
}
