package xmldsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/lafriks/go-xmldsig/v2/etreeutils"

	"github.com/beevik/etree"
)

type SigningContext struct {
	Hash crypto.Hash

	// This field will be nil and unused if the SigningContext is created with
	// NewSigningContext
	KeyStore X509KeyStore

	IDAttribute   string
	Prefix        string
	Canonicalizer Canonicalizer

	// KeyInfo is an optional element to be added instead of the default
	KeyInfo *etree.Element

	// PSSOptions, when non-nil, enables RSA-PSS signing instead of PKCS#1 v1.5.
	PSSOptions *rsa.PSSOptions

	// Objects holds optional <ds:Object> elements to include in the signature.
	// Each Object whose IDAttribute attribute is set will have a corresponding
	// Reference added to SignedInfo. Objects without an ID are still appended
	// to the Signature element but are not digested.
	Objects []*etree.Element

	// ObjectReferenceTypes maps an Object's ID value to the Type attribute that
	// should be written on its <ds:Reference> in SignedInfo.
	//
	// Keys are bare ID values (without the leading '#').
	ObjectReferenceTypes map[string]string

	// XPointerIDReferences, when true, emits Reference URIs in XPointer form
	XPointerIDReferences bool

	// SignatureID, when non-empty, sets the Id attribute on the emitted
	// <Signature> element.
	SignatureID string

	// KeyStore is mutually exclusive with signer and certs
	signer crypto.Signer
	certs  [][]byte
}

func NewDefaultSigningContext(ks X509KeyStore) *SigningContext {
	return &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IDAttribute:   DefaultIDAttr,
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}
}

// NewSigningContext creates a new signing context with the given signer and certificate chain.
// Note that e.g. rsa.PrivateKey implements the crypto.Signer interface.
// The certificate chain is a slice of ASN.1 DER-encoded X.509 certificates.
// A SigningContext created with this function should not use the KeyStore field.
// It will return error if passed a nil crypto.Signer
func NewSigningContext(signer crypto.Signer, certs [][]byte) (*SigningContext, error) {
	if signer == nil {
		return nil, errors.New("signer cannot be nil for NewSigningContext")
	}
	ctx := &SigningContext{
		Hash:          crypto.SHA256,
		IDAttribute:   DefaultIDAttr,
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),

		signer: signer,
		certs:  certs,
	}
	return ctx, nil
}

func (ctx *SigningContext) getPublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	if ctx.KeyStore != nil {
		return x509.RSA
	} else {
		switch ctx.signer.Public().(type) {
		case *ecdsa.PublicKey:
			return x509.ECDSA
		case *rsa.PublicKey:
			return x509.RSA
		case ed25519.PublicKey:
			return x509.Ed25519
		}
	}

	return x509.UnknownPublicKeyAlgorithm
}

func (ctx *SigningContext) SetSignatureMethod(algorithmID string) error {
	info, ok := signatureMethodByIdentifiers[algorithmID]
	if !ok {
		return fmt.Errorf("unknown SignatureMethod: %s", algorithmID)
	}

	algo := ctx.getPublicKeyAlgorithm()
	if info.PublicKeyAlgorithm != algo {
		return fmt.Errorf("signature method %s is incompatible with %s key", algorithmID, algo)
	}

	ctx.Hash = info.Hash

	return nil
}

func (ctx *SigningContext) digest(el *etree.Element) ([]byte, error) {
	canonical, err := ctx.Canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	h := ctx.Hash
	// Ed25519 has no hash parameter (Hash == 0); use SHA-256 for reference digests.
	if h == crypto.Hash(0) {
		h = crypto.SHA256
	}
	hash := h.New()
	_, err = hash.Write(canonical)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (ctx *SigningContext) signDigest(digest []byte) ([]byte, error) {
	if ctx.KeyStore != nil {
		key, _, err := ctx.KeyStore.GetKeyPair()
		if err != nil {
			return nil, err
		}

		if ctx.PSSOptions != nil {
			opts := *ctx.PSSOptions
			opts.Hash = ctx.Hash
			rawSignature, err := rsa.SignPSS(rand.Reader, key, ctx.Hash, digest, &opts)
			if err != nil {
				return nil, err
			}
			return rawSignature, nil
		}

		rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, ctx.Hash, digest)
		if err != nil {
			return nil, err
		}

		return rawSignature, nil
	}

	var signerOpts crypto.SignerOpts
	if ctx.PSSOptions != nil {
		opts := *ctx.PSSOptions
		opts.Hash = ctx.Hash
		signerOpts = &opts
	} else {
		signerOpts = ctx.Hash
	}

	rawSignature, err := ctx.signer.Sign(rand.Reader, digest, signerOpts)
	if err != nil {
		return nil, err
	}

	if ecdsaPub, ok := ctx.signer.Public().(*ecdsa.PublicKey); ok {
		rawSignature, err = ecdsaDERToXMLDSig(rawSignature, ecdsaPub.Curve)
		if err != nil {
			return nil, err
		}
	}

	return rawSignature, nil
}

// signCanonical signs the canonical bytes of a SignedInfo element.
func (ctx *SigningContext) signCanonical(canonical []byte) ([]byte, error) {
	if ctx.getPublicKeyAlgorithm() == x509.Ed25519 {
		// Ed25519 signs the raw message; crypto.Hash(0) signals no prehashing.
		return ctx.signer.Sign(rand.Reader, canonical, crypto.Hash(0))
	}

	h := ctx.Hash.New()
	h.Write(canonical)
	return ctx.signDigest(h.Sum(nil))
}

// generateID returns a random ID that is a valid XML NCName.
func generateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("id-%x", b), nil
}

// needsSignatureID reports whether any SignatureProperty in ctx.Objects has an
// empty Target attribute, meaning an auto-generated Signature ID is required.
func (ctx *SigningContext) needsSignatureID() bool {
	for _, obj := range ctx.Objects {
		for _, sp := range obj.FindElements(".//" + SignaturePropertyTag) {
			if sp.SelectAttrValue("Target", "") == "" {
				return true
			}
		}
	}
	return false
}

// ecdsaDERToXMLDSig converts a DER/ASN.1-encoded ECDSA signature to the fixed-width
// r||s format required by XMLDSig (RFC 4050 §3.3). Each of r and s is zero-padded
// to ceil(bitSize/8) bytes and concatenated.
func ecdsaDERToXMLDSig(der []byte, curve elliptic.Curve) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("invalid ECDSA signature: trailing data")
	}
	if sig.R == nil || sig.S == nil {
		return nil, errors.New("invalid ECDSA signature: missing r or s")
	}

	byteLen := (curve.Params().BitSize + 7) / 8
	if sig.R.BitLen() > byteLen*8 || sig.S.BitLen() > byteLen*8 {
		return nil, errors.New("invalid ECDSA signature: r or s exceeds curve order")
	}

	out := make([]byte, byteLen*2)
	sig.R.FillBytes(out[:byteLen])
	sig.S.FillBytes(out[byteLen:])
	return out, nil
}

func ecdsaXMLDSigToDER(sig []byte, curve elliptic.Curve) ([]byte, error) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(sig) != byteLen*2 {
		return sig, nil
	}
	r := new(big.Int).SetBytes(sig[:byteLen])
	s := new(big.Int).SetBytes(sig[byteLen:])
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// GetCertificates returns the DER-encoded certificate chain from the signing
// context. The first certificate is the signer's certificate.
func (ctx *SigningContext) GetCertificates() ([][]byte, error) {
	return ctx.getCerts()
}

func (ctx *SigningContext) getCerts() ([][]byte, error) {
	if ctx.KeyStore != nil {
		if cs, ok := ctx.KeyStore.(X509ChainStore); ok {
			return cs.GetChain()
		}

		_, cert, err := ctx.KeyStore.GetKeyPair()
		if err != nil {
			return nil, err
		}

		return [][]byte{cert}, nil
	} else {
		return ctx.certs, nil
	}
}

func (ctx *SigningContext) constructSignedInfo(els []*etree.Element, enveloped bool) (*etree.Element, error) {
	digestAlgorithmIdentifier := ctx.GetDigestAlgorithmIdentifier()
	if digestAlgorithmIdentifier == "" {
		return nil, errors.New("unsupported hash mechanism")
	}

	signatureMethodIdentifier := ctx.GetSignatureMethodIdentifier()
	if signatureMethodIdentifier == "" {
		return nil, errors.New("unsupported signature method")
	}

	signedInfo := &etree.Element{
		Tag:   SignedInfoTag,
		Space: ctx.Prefix,
	}

	// /SignedInfo/CanonicalizationMethod
	ctx.createNamespacedElement(signedInfo, CanonicalizationMethodTag).
		CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))

	// /SignedInfo/SignatureMethod
	signatureMethodEl := ctx.createNamespacedElement(signedInfo, SignatureMethodTag)
	signatureMethodEl.CreateAttr(AlgorithmAttr, signatureMethodIdentifier)
	if ctx.PSSOptions != nil {
		digestURI := digestAlgorithmIdentifier
		saltLen := ctx.PSSOptions.SaltLength
		if saltLen == rsa.PSSSaltLengthAuto || saltLen == rsa.PSSSaltLengthEqualsHash {
			saltLen = ctx.Hash.Size()
		}

		// RSAPSSParams namespace
		const pssNS = "http://www.w3.org/2007/05/xmldsig-more#"
		pssParams := signatureMethodEl.CreateElement("RSAPSSParams")
		pssParams.CreateAttr("xmlns", pssNS)

		digestMethodEl := pssParams.CreateElement("DigestMethod")
		digestMethodEl.CreateAttr("xmlns", Namespace)
		digestMethodEl.CreateAttr(AlgorithmAttr, digestURI)

		mgfEl := pssParams.CreateElement("MaskGenerationFunction")
		mgfEl.CreateAttr(AlgorithmAttr, RSAPSS_MGF1URI)
		mgfDigestEl := mgfEl.CreateElement("DigestMethod")
		mgfDigestEl.CreateAttr("xmlns", Namespace)
		mgfDigestEl.CreateAttr(AlgorithmAttr, digestURI)

		saltEl := pssParams.CreateElement("SaltLength")
		saltEl.SetText(fmt.Sprintf("%d", saltLen))

		trailerEl := pssParams.CreateElement("TrailerField")
		trailerEl.SetText("1")
	}

	// /SignedInfo/Reference
	for _, el := range els {
		reference := ctx.createNamespacedElement(signedInfo, ReferenceTag)

		if alg := ctx.Canonicalizer.Algorithm(); alg == CanonicalXML11AlgorithmID || alg == CanonicalXML11WithCommentsAlgorithmID {
			// When using xml-c14n11 (ie, non-exclusive canonicalization) the canonical form
			// of the element must declare all namespaces that are in scope at it's final
			// enveloped location in the document. In order to do that, we're going to construct
			// a series of cascading NSContexts to capture namespace declarations:

			// First get the context surrounding the element we are signing.
			rootNSCtx, err := etreeutils.NSBuildParentContext(el)
			if err != nil {
				return nil, err
			}

			// Then capture any declarations on the element itself.
			digestNSCtx, err := rootNSCtx.SubContext(el)
			if err != nil {
				return nil, err
			}

			// Finally detatch the element in order to capture all of the namespace
			// declarations in the scope we've constructed.
			el, err = etreeutils.NSDetatch(digestNSCtx, el)
			if err != nil {
				return nil, err
			}
		}

		digest, err := ctx.digest(el)
		if err != nil {
			return nil, err
		}

		if id := el.SelectAttrValue(ctx.IDAttribute, ""); id == "" {
			if ctx.XPointerIDReferences {
				reference.CreateAttr(URIAttr, "#xpointer(/)")
			} else {
				reference.CreateAttr(URIAttr, "")
			}
		} else if ctx.XPointerIDReferences {
			reference.CreateAttr(URIAttr, "#xpointer(id('"+id+"'))")
		} else {
			reference.CreateAttr(URIAttr, "#"+id)
		}

		// /SignedInfo/Reference/Transforms
		transforms := ctx.createNamespacedElement(reference, TransformsTag)
		if enveloped {
			ctx.createNamespacedElement(transforms, TransformTag).
				CreateAttr(AlgorithmAttr, EnvelopedSignatureAlgorithmID.String())
		}
		ctx.createNamespacedElement(transforms, TransformTag).
			CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))

		// /SignedInfo/Reference/DigestMethod
		ctx.createNamespacedElement(reference, DigestMethodTag).
			CreateAttr(AlgorithmAttr, digestAlgorithmIdentifier)

		// /SignedInfo/Reference/DigestValue
		ctx.createNamespacedElement(reference, DigestValueTag).
			SetText(base64.StdEncoding.EncodeToString(digest))
	}

	// /SignedInfo/Reference entries for ctx.Objects that have an ID attribute,
	// or whose <SignatureProperties> child has an ID attribute.
	for _, obj := range ctx.Objects {
		var nsWrapper *etree.Element
		if ctx.Prefix != "" {
			nsWrapper = etree.NewElement("_ns_")
			nsWrapper.CreateAttr("xmlns:"+ctx.Prefix, Namespace)
			nsWrapper.AddChild(obj)
		}

		id := obj.SelectAttrValue(ctx.IDAttribute, "")
		refEl := obj
		if id == "" {
			// Search all descendants for the first element that carries an ID
			// attribute. This handles both <ds:SignatureProperties> (XMLDSig §6.7)
			// and XAdES-style objects where the referenced element
			// (e.g. <xades:SignedProperties>) is nested deeper inside the Object.
			for _, desc := range obj.FindElements(".//*") {
				if childID := desc.SelectAttrValue(ctx.IDAttribute, ""); childID != "" {
					id = childID
					refEl = desc
					break
				}
			}
		}

		var objDigest []byte
		if id != "" {
			var err error
			objDigest, err = ctx.digest(refEl)
			if nsWrapper != nil {
				nsWrapper.RemoveChild(obj)
			}
			if err != nil {
				return nil, err
			}
		} else {
			if nsWrapper != nil {
				nsWrapper.RemoveChild(obj)
			}
			continue
		}

		objRef := ctx.createNamespacedElement(signedInfo, ReferenceTag)
		if refType := ctx.ObjectReferenceTypes[id]; refType != "" {
			objRef.CreateAttr("Type", refType)
		}
		if ctx.XPointerIDReferences {
			objRef.CreateAttr(URIAttr, "#xpointer(id('"+id+"'))")
		} else {
			objRef.CreateAttr(URIAttr, "#"+id)
		}

		objTransforms := ctx.createNamespacedElement(objRef, TransformsTag)
		ctx.createNamespacedElement(objTransforms, TransformTag).
			CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))

		ctx.createNamespacedElement(objRef, DigestMethodTag).
			CreateAttr(AlgorithmAttr, digestAlgorithmIdentifier)
		ctx.createNamespacedElement(objRef, DigestValueTag).
			SetText(base64.StdEncoding.EncodeToString(objDigest))
	}

	return signedInfo, nil
}

// ConstructSignature constructs a signature element for the given elements.
func (ctx *SigningContext) ConstructSignature(parent *etree.Element, el []*etree.Element, enveloped bool) (*etree.Element, error) {
	if len(el) == 0 {
		el = []*etree.Element{parent}
	}
	if len(el) > 1 || el[0] != parent {
		for _, e := range el {
			if e.SelectAttrValue(ctx.IDAttribute, "") == "" {
				return nil, errors.New("all elements to sign must have an ID")
			}
		}
	}

	// If SignatureID is not set but Objects contain <SignatureProperty> elements that
	// need a Target URI, auto-generate a random ID and back-patch the Target attributes.
	signatureID := ctx.SignatureID
	if signatureID == "" && ctx.needsSignatureID() {
		var err error
		signatureID, err = generateID()
		if err != nil {
			return nil, err
		}
	}
	if signatureID != "" {
		target := "#" + signatureID
		for _, obj := range ctx.Objects {
			for _, sp := range obj.FindElements(".//" + SignaturePropertyTag) {
				if sp.SelectAttrValue("Target", "") == "" {
					sp.CreateAttr("Target", target)
				}
			}
		}
	}

	signedInfo, err := ctx.constructSignedInfo(el, enveloped)
	if err != nil {
		return nil, err
	}

	sig := &etree.Element{
		Tag:   SignatureTag,
		Space: ctx.Prefix,
	}

	xmlns := "xmlns"
	if ctx.Prefix != "" {
		xmlns += ":" + ctx.Prefix
	}

	sig.CreateAttr(xmlns, Namespace)
	if signatureID != "" {
		sig.CreateAttr(ctx.IDAttribute, signatureID)
	}
	sig.AddChild(signedInfo)

	// Default NSContext for the SignedInfo element.
	elNSCtx := etreeutils.NewDefaultNSContext()

	if alg := ctx.Canonicalizer.Algorithm(); alg == CanonicalXML11AlgorithmID || alg == CanonicalXML11WithCommentsAlgorithmID {
		// When using xml-c14n11 (ie, non-exclusive canonicalization) the canonical form
		// of the SignedInfo must declare all namespaces that are in scope at it's final
		// enveloped location in the document. In order to do that, we're going to construct
		// a series of cascading NSContexts to capture namespace declarations:

		// First get the context surrounding the element we are signing.
		rootNSCtx, err := etreeutils.NSBuildParentContext(parent)
		if err != nil {
			return nil, err
		}

		// Then capture any declarations on the element itself.
		elNSCtx, err = rootNSCtx.SubContext(parent)
		if err != nil {
			return nil, err
		}
	}

	// Create a subcontext of the element context to capture any declarations
	sigNSCtx, err := elNSCtx.SubContext(sig)
	if err != nil {
		return nil, err
	}

	// Finally detatch the SignedInfo in order to capture all of the namespace
	// declarations in the scope we've constructed.
	detatchedSignedInfo, err := etreeutils.NSDetatch(sigNSCtx, signedInfo)
	if err != nil {
		return nil, err
	}

	canonical, err := ctx.Canonicalizer.Canonicalize(detatchedSignedInfo)
	if err != nil {
		return nil, err
	}

	rawSignature, err := ctx.signCanonical(canonical)
	if err != nil {
		return nil, err
	}

	ctx.createNamespacedElement(sig, SignatureValueTag).
		SetText(base64.StdEncoding.EncodeToString(rawSignature))

	keyInfo := ctx.createNamespacedElement(sig, KeyInfoTag)
	if ctx.KeyInfo != nil {
		// Copy the key info from the context into the signature
		for _, attr := range ctx.KeyInfo.Attr {
			keyInfo.CreateAttr(attr.FullKey(), attr.Value)
		}
		for _, c := range ctx.KeyInfo.ChildElements() {
			keyInfo.AddChild(c.Copy())
		}
	} else {
		certs, err := ctx.getCerts()
		if err != nil {
			return nil, err
		}

		x509Data := ctx.createNamespacedElement(keyInfo, X509DataTag)
		for _, cert := range certs {
			ctx.createNamespacedElement(x509Data, X509CertificateTag).
				SetText(base64.StdEncoding.EncodeToString(cert))
		}
	}

	// Append Object elements after KeyInfo.
	for _, obj := range ctx.Objects {
		sig.AddChild(obj.Copy())
	}

	return sig, nil
}

func (ctx *SigningContext) createNamespacedElement(el *etree.Element, tag string) *etree.Element {
	child := el.CreateElement(tag)
	child.Space = ctx.Prefix
	return child
}

// CreateObject constructs a <ds:Object> element using the signing context's
// namespace prefix and ID attribute. Set id to "" for an Object that will not
// be independently referenced from SignedInfo. Pass content elements to embed
// inside the Object; they are added as children.
func (ctx *SigningContext) CreateObject(id, mimeType string, content ...*etree.Element) *etree.Element {
	obj := etree.NewElement(ObjectTag)
	obj.Space = ctx.Prefix
	if id != "" {
		obj.CreateAttr(ctx.IDAttribute, id)
	}
	if mimeType != "" {
		obj.CreateAttr("MimeType", mimeType)
	}
	for _, c := range content {
		obj.AddChild(c.Copy())
	}
	return obj
}

// CreateSignatureProperties builds a <ds:Object> containing a
// <ds:SignatureProperties> element, ready to be appended to ctx.Objects.
//
// propertiesID is the Id placed on <SignatureProperties> itself — this is what
// should appear as the Reference URI in SignedInfo, so it must be non-empty for
// the properties to be signed. objectID is the Id on the wrapping <Object>;
// it may be empty if the Object does not need its own independent reference.
//
// Each property is an etree element that becomes the inner content of a
// <ds:SignatureProperty>. The Target attribute of each <SignatureProperty> is
// set to "#"+ctx.SignatureID if that field is non-empty; otherwise it is left
// blank and ConstructSignature will fill it in automatically with an
// auto-generated Signature ID.
//
// Typical usage:
//
//	ts := etree.NewElement("ts:Timestamp")
//	ts.SetText("2026-05-22T17:38:00Z")
//	ctx.Objects = append(ctx.Objects, ctx.CreateSignatureProperties("props-1", "", ts))
//	signed, err := ctx.SignEnveloped(root)
func (ctx *SigningContext) CreateSignatureProperties(propertiesID, objectID string, properties ...*etree.Element) *etree.Element {
	obj := etree.NewElement(ObjectTag)
	obj.Space = ctx.Prefix
	if objectID != "" {
		obj.CreateAttr(ctx.IDAttribute, objectID)
	}

	sigProps := etree.NewElement(SignaturePropertiesTag)
	sigProps.Space = ctx.Prefix
	if propertiesID != "" {
		sigProps.CreateAttr(ctx.IDAttribute, propertiesID)
	}

	target := ""
	if ctx.SignatureID != "" {
		target = "#" + ctx.SignatureID
	}

	for _, prop := range properties {
		sp := etree.NewElement(SignaturePropertyTag)
		sp.Space = ctx.Prefix
		sp.CreateAttr("Target", target)
		if id := prop.SelectAttrValue(ctx.IDAttribute, ""); id != "" {
			sp.CreateAttr(ctx.IDAttribute, id)
		}
		sp.AddChild(prop.Copy())
		sigProps.AddChild(sp)
	}

	obj.AddChild(sigProps)
	return obj
}

// SignEnveloped signs the given elements and returns a new element with the signature appended to parent element.
func (ctx *SigningContext) SignEnveloped(parent *etree.Element, el ...*etree.Element) (*etree.Element, error) {
	if len(el) == 0 {
		el = []*etree.Element{parent}
	}
	sig, err := ctx.ConstructSignature(parent, el, true)
	if err != nil {
		return nil, err
	}

	ret := parent.Copy()
	ret.Child = append(ret.Child, sig)

	return ret, nil
}

// Sign the given elements and returns a new element with the signature appended to parent element.
func (ctx *SigningContext) Sign(parent *etree.Element, el ...*etree.Element) (*etree.Element, error) {
	if len(el) == 0 {
		el = []*etree.Element{parent}
	}
	sig, err := ctx.ConstructSignature(parent, el, false)
	if err != nil {
		return nil, err
	}

	ret := parent.Copy()
	ret.Child = append(ret.Child, sig)

	return ret, nil
}

func (ctx *SigningContext) GetSignatureMethodIdentifier() string {
	if ctx.PSSOptions != nil {
		return RSAPSSSignatureMethod
	}

	algo := ctx.getPublicKeyAlgorithm()

	if ident, ok := signatureMethodIdentifiers[algo][ctx.Hash]; ok {
		return ident
	}
	return ""
}

// SetPSSSignatureMethod configures RSA-PSS signing with the given hash algorithm.
// It sets PSSOptions with PSSSaltLengthEqualsHash (the RFC 6931 default) and
// updates Hash to match. Returns an error if the key is not RSA.
func (ctx *SigningContext) SetPSSSignatureMethod(hash crypto.Hash) error {
	if algo := ctx.getPublicKeyAlgorithm(); algo != x509.RSA {
		return fmt.Errorf("RSA-PSS requires an RSA key, got %s", algo)
	}
	ctx.Hash = hash
	ctx.PSSOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hash,
	}
	return nil
}

func (ctx *SigningContext) GetDigestAlgorithmIdentifier() string {
	h := ctx.Hash
	// Ed25519 has no hash parameter (Hash == 0); use SHA-256 for reference digests.
	if h == crypto.Hash(0) {
		h = crypto.SHA256
	}
	if ident, ok := digestAlgorithmIdentifiers[h]; ok {
		return ident
	}
	return ""
}

// Useful for signing query string (including DEFLATED AuthnRequest) when
// using HTTP-Redirect to make a signed request.
// See 3.4.4.1 DEFLATE Encoding of https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
func (ctx *SigningContext) SignString(content string) ([]byte, error) {
	hash := ctx.Hash.New()
	if ln, err := hash.Write([]byte(content)); err != nil {
		return nil, fmt.Errorf("error calculating hash: %v", err)
	} else if ln < 1 {
		return nil, errors.New("zero length hash")
	}
	digest := hash.Sum(nil)

	return ctx.signDigest(digest)
}
