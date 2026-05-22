package xmldsig

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
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
	require.Equal(t, CanonicalXML11AlgorithmID.String(), canonicalizationMethodAttr.Value)

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
	require.Equal(t, EnvelopedSignatureAlgorithmID.String(), algorithmAttr.Value)

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
		IDAttribute: DefaultIDAttr,
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
		IDAttribute:   "OtherID",
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

func TestSignAndValidateWithECDSA(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(ecdsaCert), []byte(ecdsaKey))
	require.NoError(t, err)

	signingCtx, err := NewSigningContext(cert.PrivateKey.(crypto.Signer), cert.Certificate)
	require.NoError(t, err)

	err = signingCtx.SetSignatureMethod(ECDSASHA256SignatureMethod)
	require.NoError(t, err)

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "test-id-1")

	signed, err := signingCtx.SignEnveloped(el)
	require.NoError(t, err)

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	certStore := MemoryX509CertificateStore{
		Roots: []*x509.Certificate{x509Cert},
	}

	// Use a time within the test certificate's validity period (2019-06-13 to 2021-06-12).
	vc := NewTestValidationContext(&certStore, time.Unix(1623328519, 0))
	validated, err := vc.Validate(signed)
	require.NoError(t, err)
	require.Len(t, validated, 1)
}

func TestSignRefs(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)
	ctx.IDAttribute = "u:Id"
	ctx.Prefix = ""
	ctx.Canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
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
	valctx.IDAttribute = "u:Id"
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

func TestSignAndValidateRSAPSSWithKeyStore(t *testing.T) {
	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	ctx := NewDefaultSigningContext(ks)

	err := ctx.SetPSSSignatureMethod(crypto.SHA256)
	require.NoError(t, err)

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "pss-test-1")

	signed, err := ctx.SignEnveloped(el)
	require.NoError(t, err)

	// Verify the SignatureMethod URI is the PSS URI.
	sigMethodEl := signed.FindElement("//" + SignatureMethodTag)
	require.NotNil(t, sigMethodEl)
	require.Equal(t, RSAPSSSignatureMethod, sigMethodEl.SelectAttrValue(AlgorithmAttr, ""))

	// Verify RSAPSSParams child element is present.
	pssParams := sigMethodEl.FindElement("RSAPSSParams")
	require.NotNil(t, pssParams)

	cert, err := x509.ParseCertificate(ks.cert)
	require.NoError(t, err)

	certStore := MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	vc := NewTestValidationContext(&certStore, time.Now())
	validated, err := vc.Validate(signed)
	require.NoError(t, err)
	require.Len(t, validated, 1)
}

func TestSignAndValidateRSAPSSWithSigner(t *testing.T) {
	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	ctx, err := NewSigningContext(ks.privateKey, [][]byte{ks.cert})
	require.NoError(t, err)

	err = ctx.SetPSSSignatureMethod(crypto.SHA384)
	require.NoError(t, err)

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "pss-test-signer-1")

	signed, err := ctx.SignEnveloped(el)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(ks.cert)
	require.NoError(t, err)

	certStore := MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	vc := NewTestValidationContext(&certStore, time.Now())
	validated, err := vc.Validate(signed)
	require.NoError(t, err)
	require.Len(t, validated, 1)
}

func TestSetPSSSignatureMethodRejectsNonRSA(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(ecdsaCert), []byte(ecdsaKey))
	require.NoError(t, err)

	ctx, err := NewSigningContext(cert.PrivateKey.(crypto.Signer), cert.Certificate)
	require.NoError(t, err)

	err = ctx.SetPSSSignatureMethod(crypto.SHA256)
	require.Error(t, err)
}

// generateEd25519Cert creates a self-signed Ed25519 certificate for testing.
func generateEd25519Cert(t *testing.T) (ed25519.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ed25519"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return priv, cert, certDER
}

func TestSignAndValidateEd25519(t *testing.T) {
	priv, cert, certDER := generateEd25519Cert(t)

	ctx, err := NewSigningContext(priv, [][]byte{certDER})
	require.NoError(t, err)

	err = ctx.SetSignatureMethod(EdDSAEd25519SignatureMethod)
	require.NoError(t, err)

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "ed25519-test-1")

	signed, err := ctx.SignEnveloped(el)
	require.NoError(t, err)

	// Verify the SignatureMethod URI.
	sigMethodEl := signed.FindElement("//" + SignatureMethodTag)
	require.NotNil(t, sigMethodEl)
	require.Equal(t, EdDSAEd25519SignatureMethod, sigMethodEl.SelectAttrValue(AlgorithmAttr, ""))

	certStore := MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	vc := NewTestValidationContext(&certStore, time.Now())
	validated, err := vc.Validate(signed)
	require.NoError(t, err)
	require.Len(t, validated, 1)
}

func TestSetSignatureMethodRejectsEd25519ForRSAKey(t *testing.T) {
	ks := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	ctx, err := NewSigningContext(ks.privateKey, [][]byte{ks.cert})
	require.NoError(t, err)

	err = ctx.SetSignatureMethod(EdDSAEd25519SignatureMethod)
	require.Error(t, err)
}

func TestSignWithObjectAndValidate(t *testing.T) {
	ks := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(ks)
	ctx.IDAttribute = "ID"

	obj := ctx.CreateObject("obj-1", "text/plain")
	obj.SetText("hello world")
	ctx.Objects = append(ctx.Objects, obj)

	root := &etree.Element{Tag: "Root"}
	root.CreateAttr("ID", "root-1")

	sig, err := ctx.ConstructSignature(root, []*etree.Element{root}, true)
	require.NoError(t, err)

	// Object element must be present inside the Signature.
	objEl := sig.FindElement("//Object")
	require.NotNil(t, objEl)
	require.Equal(t, "obj-1", objEl.SelectAttrValue("ID", ""))

	// There must be two References: one for root, one for the Object.
	refs := sig.FindElements("//SignedInfo/Reference")
	require.Len(t, refs, 2)
	uris := []string{
		refs[0].SelectAttrValue("URI", ""),
		refs[1].SelectAttrValue("URI", ""),
	}
	require.Contains(t, uris, "#obj-1")
}

func TestSignWithObjectNoID(t *testing.T) {
	ks := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(ks)
	ctx.IDAttribute = "ID"

	// Object without an ID — should be appended but not referenced.
	obj := ctx.CreateObject("", "")
	obj.SetText("anonymous content")
	ctx.Objects = append(ctx.Objects, obj)

	root := &etree.Element{Tag: "Root"}
	root.CreateAttr("ID", "root-2")

	sig, err := ctx.ConstructSignature(root, []*etree.Element{root}, true)
	require.NoError(t, err)

	objEl := sig.FindElement("//Object")
	require.NotNil(t, objEl)

	// Only one Reference (the root), not the anonymous Object.
	refs := sig.FindElements("//SignedInfo/Reference")
	require.Len(t, refs, 1)
}

func TestKeyInfoKeyNameParsed(t *testing.T) {
	raw := `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <Reference URI="#x"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AAAA</DigestValue></Reference>
  </SignedInfo>
  <SignatureValue>AAAA</SignatureValue>
  <KeyInfo>
    <KeyName>my-key-name</KeyName>
  </KeyInfo>
</Signature>`

	var sig Signature
	err := xml.Unmarshal([]byte(raw), &sig)
	require.NoError(t, err)
	require.NotNil(t, sig.KeyInfo)
	require.Equal(t, "my-key-name", sig.KeyInfo.KeyName)
}

func TestX509DataExtendedFieldsParsed(t *testing.T) {
	raw := `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <Reference URI="#x"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AAAA</DigestValue></Reference>
  </SignedInfo>
  <SignatureValue>AAAA</SignatureValue>
  <KeyInfo>
    <X509Data>
      <X509IssuerSerial>
        <X509IssuerName>CN=Test CA</X509IssuerName>
        <X509SerialNumber>42</X509SerialNumber>
      </X509IssuerSerial>
      <X509SKI>c2tpYmFzZTY0</X509SKI>
      <X509SubjectName>CN=Test</X509SubjectName>
      <X509CRL>Y3JsYmFzZTY0</X509CRL>
    </X509Data>
  </KeyInfo>
</Signature>`

	var sig Signature
	err := xml.Unmarshal([]byte(raw), &sig)
	require.NoError(t, err)
	require.NotNil(t, sig.KeyInfo)
	require.Len(t, sig.KeyInfo.X509Data.IssuerSerials, 1)
	require.Equal(t, "CN=Test CA", sig.KeyInfo.X509Data.IssuerSerials[0].IssuerName)
	require.Equal(t, "42", sig.KeyInfo.X509Data.IssuerSerials[0].SerialNumber)
	require.Equal(t, []string{"c2tpYmFzZTY0"}, sig.KeyInfo.X509Data.SKIs)
	require.Equal(t, []string{"CN=Test"}, sig.KeyInfo.X509Data.SubjectNames)
	require.Equal(t, []string{"Y3JsYmFzZTY0"}, sig.KeyInfo.X509Data.CRLs)
}
