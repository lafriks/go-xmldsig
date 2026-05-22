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

	// KeyStore is mutually exclusive with signer and certs
	signer crypto.Signer
	certs  [][]byte
}

func NewDefaultSigningContext(ks X509KeyStore) *SigningContext {
	return &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IDAttribute:   DefaultIdAttr,
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
		IDAttribute:   DefaultIdAttr,
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
			reference.CreateAttr(URIAttr, "")
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

	return sig, nil
}

func (ctx *SigningContext) createNamespacedElement(el *etree.Element, tag string) *etree.Element {
	child := el.CreateElement(tag)
	child.Space = ctx.Prefix
	return child
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
