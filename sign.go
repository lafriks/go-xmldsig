package xmldsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/lafriks/go-xmldsig/etreeutils"

	"github.com/beevik/etree"
)

type SigningContext struct {
	Hash crypto.Hash

	// This field will be nil and unused if the SigningContext is created with
	// NewSigningContext
	KeyStore X509KeyStore

	IdAttribute   string
	Prefix        string
	Canonicalizer Canonicalizer

	// KeyInfo is an optional element to be added instead of the default
	KeyInfo *etree.Element

	// KeyStore is mutually exclusive with signer and certs
	signer crypto.Signer
	certs  [][]byte
}

func NewDefaultSigningContext(ks X509KeyStore) *SigningContext {
	return &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   DefaultIdAttr,
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
		IdAttribute:   DefaultIdAttr,
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

	hash := ctx.Hash.New()
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

		rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, ctx.Hash, digest)
		if err != nil {
			return nil, err
		}

		return rawSignature, nil
	} else {
		rawSignature, err := ctx.signer.Sign(rand.Reader, digest, ctx.Hash)
		if err != nil {
			return nil, err
		}

		return rawSignature, nil
	}
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
	ctx.createNamespacedElement(signedInfo, SignatureMethodTag).
		CreateAttr(AlgorithmAttr, signatureMethodIdentifier)

	// /SignedInfo/Reference
	for _, el := range els {
		reference := ctx.createNamespacedElement(signedInfo, ReferenceTag)

		if alg := ctx.Canonicalizer.Algorithm(); alg == CanonicalXML11AlgorithmId || alg == CanonicalXML11WithCommentsAlgorithmId {
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

		dataId := el.SelectAttrValue(ctx.IdAttribute, "")
		if dataId == "" {
			reference.CreateAttr(URIAttr, "")
		} else {
			reference.CreateAttr(URIAttr, "#"+dataId)
		}

		// /SignedInfo/Reference/Transforms
		transforms := ctx.createNamespacedElement(reference, TransformsTag)
		if enveloped {
			ctx.createNamespacedElement(transforms, TransformTag).
				CreateAttr(AlgorithmAttr, EnvelopedSignatureAltorithmId.String())
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
			if e.SelectAttrValue(ctx.IdAttribute, "") == "" {
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
	elNSCtx := etreeutils.DefaultNSContext

	if alg := ctx.Canonicalizer.Algorithm(); alg == CanonicalXML11AlgorithmId || alg == CanonicalXML11WithCommentsAlgorithmId {
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

	digest, err := ctx.digest(detatchedSignedInfo)
	if err != nil {
		return nil, err
	}

	rawSignature, err := ctx.signDigest(digest)
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
	algo := ctx.getPublicKeyAlgorithm()

	if ident, ok := signatureMethodIdentifiers[algo][ctx.Hash]; ok {
		return ident
	}
	return ""
}

func (ctx *SigningContext) GetDigestAlgorithmIdentifier() string {
	if ident, ok := digestAlgorithmIdentifiers[ctx.Hash]; ok {
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
