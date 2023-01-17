package xmldsig

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)
	testSignWithContext(t, ctx, RSASHA256SignatureMethod, crypto.SHA256)
}

func TestNewSigningContext(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	ctx, err := NewSigningContext(randomKeyStore.privateKey, [][]byte{randomKeyStore.cert})
	require.NoError(t, err)
	testSignWithContext(t, ctx, RSASHA256SignatureMethod, crypto.SHA256)
}

func testSignWithContext(t *testing.T, ctx *SigningContext, sigMethodID string, digestAlgo crypto.Hash) {
	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	id := "_97e34c50-65ec-4132-8b39-02933960a96a"
	authnRequest.CreateAttr("ID", id)
	authnRequest.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	hash := digestAlgo.New()
	canonicalized, err := ctx.Canonicalizer.Canonicalize(authnRequest)
	require.NoError(t, err)

	_, err = hash.Write(canonicalized)
	require.NoError(t, err)
	digest := hash.Sum(nil)

	signed, err := ctx.SignEnveloped(authnRequest)
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	sig := signed.FindElement("//" + SignatureTag)
	require.NotEmpty(t, sig)

	signedInfo := sig.FindElement("//" + SignedInfoTag)
	require.NotEmpty(t, signedInfo)

	canonicalizationMethodElement := signedInfo.FindElement("//" + CanonicalizationMethodTag)
	require.NotEmpty(t, canonicalizationMethodElement)

	canonicalizationMethodAttr := canonicalizationMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, canonicalizationMethodAttr)
	require.Equal(t, CanonicalXML11AlgorithmId.String(), canonicalizationMethodAttr.Value)

	signatureMethodElement := signedInfo.FindElement("//" + SignatureMethodTag)
	require.NotEmpty(t, signatureMethodElement)

	signatureMethodAttr := signatureMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, signatureMethodAttr)
	require.Equal(t, sigMethodID, signatureMethodAttr.Value)

	referenceElement := signedInfo.FindElement("//" + ReferenceTag)
	require.NotEmpty(t, referenceElement)

	idAttr := referenceElement.SelectAttr(URIAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, "#"+id, idAttr.Value)

	transformsElement := referenceElement.FindElement("//" + TransformsTag)
	require.NotEmpty(t, transformsElement)

	transformElement := transformsElement.FindElement("//" + TransformTag)
	require.NotEmpty(t, transformElement)

	algorithmAttr := transformElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, EnvelopedSignatureAltorithmId.String(), algorithmAttr.Value)

	digestMethodElement := referenceElement.FindElement("//" + DigestMethodTag)
	require.NotEmpty(t, digestMethodElement)

	digestMethodAttr := digestMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, digestMethodElement)
	require.Equal(t, digestAlgorithmIdentifiers[digestAlgo], digestMethodAttr.Value)

	digestValueElement := referenceElement.FindElement("//" + DigestValueTag)
	require.NotEmpty(t, digestValueElement)
	require.Equal(t, base64.StdEncoding.EncodeToString(digest), digestValueElement.Text())
}

func TestSignErrors(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:        crypto.SHA512_256,
		KeyStore:    randomKeyStore,
		IdAttribute: DefaultIdAttr,
		Prefix:      DefaultPrefix,
	}

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	_, err := ctx.SignEnveloped(authnRequest)
	require.Error(t, err)
}

func TestSignNonDefaultID(t *testing.T) {
	// Sign a document by referencing a non-default ID attribute ("OtherID"),
	// and confirm that the signature correctly references it.
	ks := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "OtherID",
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	signable := &etree.Element{
		Space: "foo",
		Tag:   "Bar",
	}

	id := "_97e34c50-65ec-4132-8b39-02933960a96b"

	signable.CreateAttr("OtherID", id)
	signed, err := ctx.SignEnveloped(signable)
	require.NoError(t, err)

	ref := signed.FindElement("./Signature/SignedInfo/Reference")
	require.NotNil(t, ref)
	refURI := ref.SelectAttrValue("URI", "")
	require.Equal(t, refURI, "#"+id)
}

func TestIncompatibleSignatureMethods(t *testing.T) {
	// RSA
	randomKeyStore := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	ctx, err := NewSigningContext(randomKeyStore.privateKey, [][]byte{randomKeyStore.cert})
	require.NoError(t, err)

	err = ctx.SetSignatureMethod(ECDSASHA512SignatureMethod)
	require.Error(t, err)

	// ECDSA
	testECDSACert, err := tls.X509KeyPair([]byte(ecdsaCert), []byte(ecdsaKey))
	require.NoError(t, err)

	ctx, err = NewSigningContext(testECDSACert.PrivateKey.(crypto.Signer), testECDSACert.Certificate)
	require.NoError(t, err)

	err = ctx.SetSignatureMethod(RSASHA1SignatureMethod)
	require.Error(t, err)
}

func TestSignWithECDSA(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(ecdsaCert), []byte(ecdsaKey))
	require.NoError(t, err)

	ctx, err := NewSigningContext(cert.PrivateKey.(crypto.Signer), cert.Certificate)
	require.NoError(t, err)

	method := ECDSASHA512SignatureMethod
	err = ctx.SetSignatureMethod(method)
	require.NoError(t, err)

	testSignWithContext(t, ctx, method, crypto.SHA512)
}

func TestSignRefs(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)
	ctx.IdAttribute = "u:Id"
	ctx.Prefix = ""
	ctx.Canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList("") // MakeC14N11Canonicalizer()
	ctx.SetSignatureMethod(RSASHA1SignatureMethod)

	el := &etree.Element{
		Space: "s",
		Tag:   "Envelope",
	}
	el.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
	el.CreateAttr("xmlns:a", "http://www.w3.org/2005/08/addressing")
	el.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")

	h := el.CreateElement("s:Header")
	to := h.CreateElement("a:To")
	to.CreateAttr("s:mustUnderstand", "1")
	to.CreateAttr("u:Id", "_1")
	to.SetText("https://example.com/Issue.svc")

	sec := h.CreateElement("o:Security")
	sec.CreateAttr("s:mustUnderstand", "1")
	sec.CreateAttr("xmlns:o", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")

	ts := sec.CreateElement("u:Timestamp")
	ts.CreateAttr("u:Id", "_0")
	ts.CreateElement("u:Created").SetText("2018-01-01T00:00:00Z")
	ts.CreateElement("u:Expires").SetText("2018-01-01T00:05:00Z")

	bts := sec.CreateElement("o:BinarySecurityToken")
	bts.CreateAttr("u:Id", "uuid-0ebd724a-eff9-41cd-849b-99e941cb3d80-1")
	bts.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	_, certData, err := randomKeyStore.GetKeyPair()
	require.NoError(t, err)
	bts.SetText(base64.StdEncoding.EncodeToString(certData))

	ki := &etree.Element{
		Space: ctx.Prefix,
		Tag:   "KeyInfo",
	}
	ref := ki.CreateElement("o:SecurityTokenReference").CreateElement("o:Reference")
	ref.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	ref.CreateAttr("URI", "#uuid-0ebd724a-eff9-41cd-849b-99e941cb3d80-1")

	ctx.KeyInfo = ki

	sig, err := ctx.ConstructSignature(sec, []*etree.Element{to, ts}, false)
	require.NoError(t, err)

	sec.AddChild(sig)

	valctx := NewTestValidationContext(nil, time.Now())
	valctx.IdAttribute = "u:Id"
	valctx.CertificateResolver = func(sig *etree.Element) (*x509.Certificate, error) {
		ki := sig.SelectElement("KeyInfo")
		if sig == nil {
			return nil, nil
		}
		str := ki.SelectElement("SecurityTokenReference")
		if str == nil {
			return nil, nil
		}
		ref := str.SelectElement("Reference")
		if ref == nil {
			return nil, nil
		}
		if ref.SelectAttrValue("ValueType", "") != "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" {
			return nil, nil
		}
		id := ref.SelectAttrValue("URI", "")
		if id == "" {
			return nil, nil
		}
		if id[0] == '#' {
			id = id[1:]
		}
		root := sig
		for root.Parent() != nil {
			root = root.Parent()
		}
		bts := root.FindElement("//*[@u:Id='" + id + "']")
		if bts == nil {
			return nil, nil
		}
		data, err := base64.StdEncoding.DecodeString(bts.Text())
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(data)
	}

	validated, err := valctx.ValidateInsecure(el)
	require.NoError(t, err)
	require.Len(t, validated, 2)
}
