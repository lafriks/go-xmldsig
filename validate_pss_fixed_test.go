package xmldsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"

	"github.com/lafriks/go-xmldsig/v2/etreeutils"
)

// newPSSKeyStore builds a self-signed key store with an RSA key of the given
// size. SHA-512 fixed-parameter PSS needs a 64-byte salt, which does not fit a
// 1024-bit modulus, so those cases require a larger key.
func newPSSKeyStore(t *testing.T, bits int) *MemoryX509KeyStore {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fixed-pss-test"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return &MemoryX509KeyStore{privateKey: key, cert: der}
}

// signFixedPSS produces an enveloped signature that uses an RFC 6931
// fixed-parameter RSASSA-PSS method URI (no RSAPSSParams element), computing the
// SignatureValue over the canonical SignedInfo with actualSalt bytes of salt.
func signFixedPSS(t *testing.T, ks *MemoryX509KeyStore, methodURI string, hash crypto.Hash, actualSalt int) (*etree.Element, *MemoryX509CertificateStore) {
	t.Helper()

	el := etree.NewElement("Root")
	el.CreateAttr("ID", "root-id")
	el.CreateElement("Child").SetText("payload")

	sctx := NewDefaultSigningContext(ks)
	signed, err := sctx.SignEnveloped(el)
	require.NoError(t, err)

	// Switch the signature method to the fixed-parameter PSS URI.
	smEl := signed.FindElement("//" + SignatureMethodTag)
	require.NotNil(t, smEl)
	smEl.CreateAttr(AlgorithmAttr, methodURI)

	// Sign the canonical SignedInfo (carrying the fixed URI) exactly as the
	// validator will recompute it.
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

	hh := hash.New()
	hh.Write(canonical)
	digest := hh.Sum(nil)
	sigVal, err := rsa.SignPSS(rand.Reader, ks.privateKey, hash, digest, &rsa.PSSOptions{
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

// TestValidateFixedParameterRSAPSS covers the RFC 6931 fixed-parameter RSASSA-PSS
// methods: each validates when signed with the mandated salt length (equal to
// the hash length), tampering is rejected, and a signature using a different
// salt length is rejected (PSSSaltLengthEqualsHash is enforced, not auto).
func TestValidateFixedParameterRSAPSS(t *testing.T) {
	cases := []struct {
		name   string
		uri    string
		hash   crypto.Hash
		bits   int
		salt   int
		expect bool
	}{
		{"sha256 valid", RSAPSSSHA256MGF1SignatureMethod, crypto.SHA256, 1024, 32, true},
		{"sha384 valid", RSAPSSSHA384MGF1SignatureMethod, crypto.SHA384, 1024, 48, true},
		{"sha512 valid", RSAPSSSHA512MGF1SignatureMethod, crypto.SHA512, 2048, 64, true},
		{"sha256 wrong salt rejected", RSAPSSSHA256MGF1SignatureMethod, crypto.SHA256, 1024, 20, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks := newPSSKeyStore(t, tc.bits)
			signed, store := signFixedPSS(t, ks, tc.uri, tc.hash, tc.salt)
			vctx := NewDefaultValidationContext(store)

			_, err := vctx.Validate(signed)
			if tc.expect {
				require.NoError(t, err)

				tampered := signed.Copy()
				tampered.FindElement("//Child").SetText("tampered")
				_, err = vctx.Validate(tampered)
				require.Error(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
