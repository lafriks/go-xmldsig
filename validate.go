package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lafriks/go-xmldsig/v2/etreeutils"

	"github.com/beevik/etree"
)

var whiteSpace = regexp.MustCompile(`\s+`)

var (
	// ErrMissingSignature indicates that no enveloped signature was found referencing
	// the top level element passed for signature verification.
	ErrMissingSignature = errors.New("missing signature referencing the top-level element")
	ErrInvalidSignature = errors.New("invalid signature")
)

type KeyInfoCertificateResolver func(sig *etree.Element) (*x509.Certificate, error)

type ValidationContext struct {
	CertificateStore    X509CertificateStore
	IDAttribute         string
	Clock               Clock
	CertificateResolver KeyInfoCertificateResolver
	// CertVerifyOptions, if set, overrides the x509.VerifyOptions used when
	// verifying the signing certificate against the trust roots. Roots and
	// CurrentTime are always set by the library; all other fields (KeyUsages,
	// DNSName, etc.) are taken from this value. When nil, KeyUsages defaults
	// to []x509.ExtKeyUsage{x509.ExtKeyUsageAny}.
	CertVerifyOptions *x509.VerifyOptions
	// MaxTraversalElements bounds the depth-first search for the Signature
	// element, as a DoS guard against adversarially large documents. 0 keeps
	// the default budget of 1000 visited elements; a negative value disables
	// the limit. Signatures that are direct children of the validated element
	// (the common enveloped shape) are found by a children-first scan that
	// does not consume this budget. Note that the deep search's budget also
	// covers reading a found signature's immediate children — size custom
	// budgets accordingly.
	MaxTraversalElements int
}

func NewDefaultValidationContext(certificateStore X509CertificateStore) *ValidationContext {
	return &ValidationContext{
		CertificateStore: certificateStore,
		IDAttribute:      DefaultIDAttr,
		Clock:            &realClock{},
	}
}

func childPath(space, tag string) string {
	if space == "" {
		return "./" + tag
	} else {
		return "./" + space + ":" + tag
	}
}

func mapPathToElement(tree, el *etree.Element) []int {
	for i, child := range tree.Child {
		if child == el {
			return []int{i}
		}
	}

	for i, child := range tree.Child {
		if childElement, ok := child.(*etree.Element); ok {
			childPath := mapPathToElement(childElement, el)
			if childPath != nil {
				return append([]int{i}, childPath...)
			}
		}
	}

	return nil
}

func removeElementAtPath(el *etree.Element, path []int) bool {
	if len(path) == 0 {
		return false
	}

	if len(el.Child) <= path[0] {
		return false
	}

	childElement, ok := el.Child[path[0]].(*etree.Element)
	if !ok {
		return false
	}

	if len(path) == 1 {
		el.RemoveChildAt(path[0])
		return true
	}

	return removeElementAtPath(childElement, path[1:])
}

// Transform returns a new element equivalent to the passed root el, but with
// the set of transformations described by the ref applied.
//
// The functionality of transform is currently very limited and purpose-specific.
func (ctx *ValidationContext) transform(
	el *etree.Element,
	sig *Signature,
	ref *Reference,
) (Canonicalizer, error) {
	transforms := ref.Transforms.Transforms

	// map the path to the passed signature relative to the passed root, in
	// order to enable removal of the signature by an enveloped signature
	// transform
	signaturePath := mapPathToElement(el, sig.UnderlyingElement())

	var canonicalizer Canonicalizer

	for _, transform := range transforms {
		algo := transform.Algorithm

		switch AlgorithmID(algo) {
		case EnvelopedSignatureAlgorithmID:
			if !removeElementAtPath(el, signaturePath) {
				return nil, errors.New("error applying canonicalization transform: Signature not found")
			}

		case CanonicalXML10ExclusiveAlgorithmID:
			var prefixList string
			if transform.InclusiveNamespaces != nil {
				prefixList = transform.InclusiveNamespaces.PrefixList
			}

			canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList)

		case CanonicalXML10ExclusiveWithCommentsAlgorithmID:
			var prefixList string
			if transform.InclusiveNamespaces != nil {
				prefixList = transform.InclusiveNamespaces.PrefixList
			}

			canonicalizer = MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList)

		case CanonicalXML11AlgorithmID:
			canonicalizer = MakeC14N11Canonicalizer()

		case CanonicalXML11WithCommentsAlgorithmID:
			canonicalizer = MakeC14N11WithCommentsCanonicalizer()

		case CanonicalXML10AlgorithmID:
			canonicalizer = MakeC14N10Canonicalizer()

		case CanonicalXML10WithCommentsAlgorithmID:
			canonicalizer = MakeC14N10WithCommentsCanonicalizer()

		case Base64TransformAlgorithmID:
			canonicalizer = MakeBase64Canonicalizer()

		default:
			return nil, errors.New("unknown transform algorithm: " + algo)
		}
	}

	if canonicalizer == nil {
		canonicalizer = MakeNullCanonicalizer()
	}

	return canonicalizer, nil
}

func findElementByID(root *etree.Element, idAttr, id string) *etree.Element {
	stack := []*etree.Element{root}
	for len(stack) > 0 {
		el := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if el.SelectAttrValue(idAttr, "") == id {
			return el
		}
		for _, token := range el.Child {
			if child, ok := token.(*etree.Element); ok {
				stack = append(stack, child)
			}
		}
	}
	return nil
}

// referenceIDAttr parses a Reference URI and returns the bare ID it targets
// or if it's root element target.
func referenceIDAttr(uri string) (string, bool, bool) {
	if uri == "" {
		return "", true, true
	}
	if uri[0] != '#' {
		return "", false, false
	}
	fragment := uri[1:]
	if strings.HasPrefix(fragment, "xpointer(") && strings.HasSuffix(fragment, ")") {
		expr := fragment[len("xpointer(") : len(fragment)-1]
		if expr == "/" {
			return "", true, true
		}
		if strings.HasPrefix(expr, "id(") && strings.HasSuffix(expr, ")") {
			inner := expr[len("id(") : len(expr)-1]
			if len(inner) >= 2 &&
				((inner[0] == '\'' && inner[len(inner)-1] == '\'') ||
					(inner[0] == '"' && inner[len(inner)-1] == '"')) {
				return inner[1 : len(inner)-1], false, true
			}
		}
		return "", false, false
	}
	return fragment, false, true
}

func (ctx *ValidationContext) validateSignature(el *etree.Element, sig *Signature, cert *x509.Certificate) ([]*etree.Element, error) {
	if sig.SignatureValue == nil {
		return nil, errors.New("missing signature value")
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(sig.SignatureValue.Data)
	if err != nil {
		return nil, fmt.Errorf("could not decode signature: %w", err)
	}

	// findSignature already replaced the SignedInfo element with its canonicalized
	// form, so canonicalSerialize gives us exactly the bytes that were signed.
	signatureElement := sig.UnderlyingElement()
	nsCtx, err := etreeutils.NSBuildParentContext(signatureElement)
	if err != nil {
		return nil, err
	}
	signedInfoEl, err := etreeutils.NSFindOneChildCtx(nsCtx, signatureElement, Namespace, SignedInfoTag)
	if err != nil {
		return nil, err
	}
	if signedInfoEl == nil {
		return nil, errors.New("missing SignedInfo")
	}
	canonicalBytes, err := canonicalSerialize(signedInfoEl)
	if err != nil {
		return nil, err
	}

	// Parse SignedInfo from the canonical bytes so that all further processing is
	// driven by exactly what was signed, not by the raw parsed etree.
	signedInfo := &SignedInfo{}
	if err := xml.Unmarshal(canonicalBytes, signedInfo); err != nil {
		return nil, fmt.Errorf("could not parse canonical SignedInfo: %w", err)
	}

	// Verify the signature against the canonical bytes.
	if signedInfo.SignatureMethod.Algorithm == RSAPSSSignatureMethod {
		// RSA-PSS: parse hash from RSAPSSParams (default SHA-256 per RFC 6931).
		hashAlgo := digestAlgorithmsByIdentifier[digestAlgorithmIdentifiers[crypto.SHA256]]
		if signedInfo.SignatureMethod.RSAPSSParams != nil {
			if h, ok := digestAlgorithmsByIdentifier[signedInfo.SignatureMethod.RSAPSSParams.DigestMethod.Algorithm]; ok {
				hashAlgo = h
			}
		}

		rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("RSA-PSS signature requires an RSA public key")
		}

		h := hashAlgo.New()
		h.Write(canonicalBytes)
		hashed := h.Sum(nil)

		if err := rsa.VerifyPSS(rsaPub, hashAlgo, hashed, decodedSignature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		}); err != nil {
			return nil, err
		}
	} else {
		algo, ok := x509SignatureAlgorithmByIdentifier[signedInfo.SignatureMethod.Algorithm]
		if !ok {
			return nil, errors.New("unknown signature method: " + signedInfo.SignatureMethod.Algorithm)
		}
		sigBytes := decodedSignature
		// XMLDSig stores ECDSA signatures as r||s (RFC 4050 §3.3), but Go's
		// x509.Certificate.CheckSignature expects DER/ASN.1. Convert if needed.
		if ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			sigBytes, err = ecdsaXMLDSigToDER(decodedSignature, ecdsaPub.Curve)
			if err != nil {
				return nil, err
			}
		}
		if err := cert.CheckSignature(algo, canonicalBytes, sigBytes); err != nil {
			return nil, err
		}
	}

	if len(signedInfo.References) == 0 {
		return nil, errors.New("SignedInfo must contain at least one Reference")
	}

	// Process each reference using the verified SignedInfo.
	validated := make([]*etree.Element, 0, len(signedInfo.References))
	for _, ref := range signedInfo.References {
		referencedEl := el

		idVal, isRoot, ok := referenceIDAttr(ref.URI)
		switch {
		case !ok:
			if len(ref.URI) > 0 && ref.URI[0] == '/' {
				// Absolute XPath path — signer-controlled, no user-supplied interpolation.
				path, err := etree.CompilePath(ref.URI)
				if err != nil {
					return nil, err
				}
				referencedEl = el.FindElementPath(path)
				if referencedEl == nil {
					return nil, errors.New("error implementing etree: " + ref.URI)
				}
			} else {
				return nil, fmt.Errorf("unsupported reference URI: %s", ref.URI)
			}
		case isRoot:
			// Reference the root element as-is.
		default:
			if el.SelectAttrValue(ctx.IDAttribute, "") != idVal {
				referencedEl = findElementByID(el, ctx.IDAttribute, idVal)
				if referencedEl == nil {
					// Check if element is in signature element
					referencedEl = findElementByID(sig.UnderlyingElement(), ctx.IDAttribute, idVal)
				}
				if referencedEl == nil {
					return nil, errors.New("referenced ID element not found: " + ref.URI)
				}
			}
		}

		// Perform all transformations listed in the 'SignedInfo'
		// Basically, this means removing the 'SignedInfo'
		canonicalizer, err := ctx.transform(referencedEl, sig, &ref)
		if err != nil {
			return nil, err
		}

		transformedEl := referencedEl

		if alg := canonicalizer.Algorithm(); alg == CanonicalXML11AlgorithmID || alg == CanonicalXML11WithCommentsAlgorithmID {
			// When using xml-c14n11 (ie, non-exclusive canonicalization) the canonical form
			// of the element must declare all namespaces that are in scope at it's final
			// enveloped location in the document. In order to do that, we're going to construct
			// a series of cascading NSContexts to capture namespace declarations:

			// First get the context surrounding the element we are signing.
			rootNSCtx, err := etreeutils.NSBuildParentContext(referencedEl)
			if err != nil {
				return nil, err
			}

			// Then capture any declarations on the element itself.
			digestNSCtx, err := rootNSCtx.SubContext(referencedEl)
			if err != nil {
				return nil, err
			}

			// Finally detatch the element in order to capture all of the namespace
			// declarations in the scope we've constructed.
			transformedEl, err = etreeutils.NSDetatch(digestNSCtx, referencedEl)
			if err != nil {
				return nil, err
			}
		}

		digestAlgorithm := ref.DigestAlgo.Algorithm

		// Digest the transformed XML and compare it to the 'DigestValue' from the 'SignedInfo'
		canonical, err := canonicalizer.Canonicalize(transformedEl)
		if err != nil {
			return nil, err
		}

		digestAlgo, ok := digestAlgorithmsByIdentifier[digestAlgorithm]
		if !ok {
			return nil, errors.New("unknown digest algorithm: " + digestAlgorithm)
		}
		h := digestAlgo.New()
		_, _ = h.Write(canonical)

		decodedDigestValue, err := base64.StdEncoding.DecodeString(ref.DigestValue)
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(h.Sum(nil), decodedDigestValue) {
			return nil, fmt.Errorf("digest is not valid for '%s'", ref.URI)
		}

		validated = append(validated, referencedEl)
	}

	return validated, nil
}

func contains(roots []*x509.Certificate, cert *x509.Certificate) bool {
	for _, root := range roots {
		if root.Equal(cert) {
			return true
		}
	}
	return false
}

// In most places, we use etree Elements, but while deserializing the Signature, we use
// encoding/xml unmarshal directly to convert to a convenient go struct. This presents a problem in some cases because
// when an xml element repeats under the parent, the last element will win and/or be appended. We need to assert that
// the Signature object matches the expected shape of a Signature object.
func validateShape(signatureEl *etree.Element) error {
	parentCtx, err := etreeutils.NSBuildParentContext(signatureEl)
	if err != nil {
		return err
	}
	sigCtx, err := parentCtx.SubContext(signatureEl)
	if err != nil {
		return err
	}

	childCounts := map[string]int{}
	for _, child := range signatureEl.ChildElements() {
		childCtx, err := sigCtx.SubContext(child)
		if err != nil {
			return err
		}
		ns, err := childCtx.LookupPrefix(child.Space)
		if err != nil || ns != Namespace {
			continue
		}
		childCounts[child.Tag]++
	}

	if childCounts[SignedInfoTag] != 1 || childCounts[SignatureValueTag] != 1 || childCounts[KeyInfoTag] > 1 {
		return ErrInvalidSignature
	}
	return nil
}

// findSignature searches for a Signature element referencing the passed root element.
func (ctx *ValidationContext) findSignature(root *etree.Element) (*Signature, error) {
	idAttrEl := root.SelectAttr(ctx.IDAttribute)
	idAttr := ""
	if idAttrEl != nil {
		idAttr = idAttrEl.Value
	}

	var sig *Signature
	var lsig *Signature

	// The children-first scan and the deep search below may both visit the
	// same Signature; canonicalizing its SignedInfo twice would corrupt it.
	processed := map[*etree.Element]bool{}

	handle := func(ctx etreeutils.NSContext, signatureEl *etree.Element) error {
		if processed[signatureEl] {
			return nil
		}
		processed[signatureEl] = true

		err := validateShape(signatureEl)
		if err != nil {
			return err
		}
		found := false
		err = etreeutils.NSFindChildrenIterateCtx(ctx, signatureEl, Namespace, SignedInfoTag,
			func(ctx etreeutils.NSContext, signedInfo *etree.Element) error {
				c14NMethod, err := etreeutils.NSFindOneChildCtx(ctx, signedInfo, Namespace, CanonicalizationMethodTag)
				if err != nil {
					return err
				}

				if c14NMethod == nil {
					return errors.New("missing CanonicalizationMethod on Signature")
				}

				c14NAlgorithm := c14NMethod.SelectAttrValue(AlgorithmAttr, "")

				var canonicalSignedInfo *etree.Element

				switch alg := AlgorithmID(c14NAlgorithm); alg {
				case CanonicalXML10ExclusiveAlgorithmID, CanonicalXML10ExclusiveWithCommentsAlgorithmID:
					detachedSignedInfo := signedInfo.Copy()
					err := etreeutils.TransformExcC14nWithContext(ctx, detachedSignedInfo, "", alg == CanonicalXML10ExclusiveWithCommentsAlgorithmID)
					if err != nil {
						return err
					}

					// NOTE: TransformExcC14n transforms the element in-place,
					// while canonicalPrep isn't meant to. Once we standardize
					// this behavior we can drop this, as well as the adding and
					// removing of elements below.
					canonicalSignedInfo = detachedSignedInfo

				case CanonicalXML11AlgorithmID, CanonicalXML11WithCommentsAlgorithmID:
					detachedSignedInfo, err := etreeutils.NSDetatch(ctx, signedInfo)
					if err != nil {
						return err
					}
					canonicalSignedInfo = canonicalPrep(detachedSignedInfo, true, alg == CanonicalXML11WithCommentsAlgorithmID)

				case CanonicalXML10AlgorithmID, CanonicalXML10WithCommentsAlgorithmID:
					canonicalSignedInfo = canonicalPrep(signedInfo, true, alg == CanonicalXML10WithCommentsAlgorithmID)

				default:
					return fmt.Errorf("invalid CanonicalizationMethod on Signature: %s", c14NAlgorithm)
				}

				signatureEl.InsertChildAt(signedInfo.Index(), canonicalSignedInfo)
				signatureEl.RemoveChild(signedInfo)

				found = true

				return etreeutils.ErrTraversalHalted
			})
		if err != nil {
			return err
		}

		if !found {
			return errors.New("missing SignedInfo")
		}

		// Unmarshal the signature into a structured Signature type
		_sig := &Signature{}
		err = etreeutils.NSUnmarshalElement(ctx, signatureEl, _sig)
		if err != nil {
			return err
		}

		lsig = _sig

		// Traverse references in the signature to determine whether it has at least
		// one reference to the top level element. If so, conclude the search.
		for _, ref := range _sig.SignedInfo.References {
			idVal, isRoot, ok := referenceIDAttr(ref.URI)
			if !ok {
				continue
			}
			if isRoot || idVal == idAttr {
				sig = _sig
				return etreeutils.ErrTraversalHalted
			}
		}

		return nil
	}

	// Enveloped signatures are direct children of the element they sign in
	// XMLDSig practice (profiles such as ETSI TS 119 612 trusted lists mandate
	// it), so scan the root's immediate children first, without a traversal
	// budget: a root-level signature is found no matter how large the
	// document is.
	err := etreeutils.NSFindChildrenIterateCtx(etreeutils.NewNSContextWithLimit(-1), root, Namespace, SignatureTag, handle)
	if err != nil {
		return nil, err
	}

	// Budgeted depth-first search for signatures that are not direct children
	// of the root.
	if sig == nil {
		nsctx := etreeutils.NewDefaultNSContext()
		if ctx.MaxTraversalElements != 0 {
			nsctx = etreeutils.NewNSContextWithLimit(ctx.MaxTraversalElements)
		}
		if err := etreeutils.NSFindIterateCtx(nsctx, root, Namespace, SignatureTag, handle); err != nil {
			return nil, err
		}
	}

	if idAttr == "" && sig == nil {
		// If no signature references the top level element, use the last signature
		// as it could be partially signed document.
		sig = lsig
	}

	if sig == nil {
		return nil, ErrMissingSignature
	}

	return sig, nil
}

func (ctx *ValidationContext) verifyCertificate(sig *Signature, check, verify bool) (*x509.Certificate, error) {
	now := ctx.Clock.Now()

	var err error
	roots := make([]*x509.Certificate, 0)

	if ctx.CertificateStore != nil {
		roots, err = ctx.CertificateStore.Certificates()
		if err != nil {
			return nil, err
		}
	}

	var cert *x509.Certificate

	if sig.KeyInfo != nil {
		// If the Signature includes KeyInfo, extract the certificate from there
		if sig.KeyInfo.X509Data != nil && len(sig.KeyInfo.X509Data.X509Certificates) != 0 && sig.KeyInfo.X509Data.X509Certificates[0].Data != "" {
			certData, err := base64.StdEncoding.DecodeString(
				whiteSpace.ReplaceAllString(sig.KeyInfo.X509Data.X509Certificates[0].Data, ""))
			if err != nil {
				return nil, errors.New("failed to parse certificate")
			}

			cert, err = x509.ParseCertificate(certData)
			if err != nil {
				return nil, err
			}
		} else if ctx.CertificateResolver != nil {
			cert, err = ctx.CertificateResolver(sig.UnderlyingElement())
			if err != nil {
				return nil, err
			}
		}
	} else if len(roots) == 1 {
		// If the Signature doesn't have KeyInfo, Use the root certificate if there is only one
		cert = roots[0]
	}

	if cert == nil {
		return nil, errors.New("missing x509 Element")
	}

	// Verify that the certificate is one we trust
	if verify {
		pool := x509.NewCertPool()
		for _, c := range roots {
			pool.AddCert(c)
		}
		var opts x509.VerifyOptions
		if ctx.CertVerifyOptions != nil {
			opts = *ctx.CertVerifyOptions
		} else {
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}
		opts.Roots = pool
		opts.CurrentTime = now

		_, err := cert.Verify(opts)
		if err != nil {
			return nil, err
		}
	} else if check && !contains(roots, cert) {
		return nil, errors.New("could not verify certificate against trusted certs")
	}

	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errors.New("certificate is not valid at this time")
	}

	return cert, nil
}

// Validate verifies that the passed element contains a valid enveloped signature
// matching a currently-valid certificate in the context's CertificateStore.
func (ctx *ValidationContext) Validate(el *etree.Element) ([]*etree.Element, error) {
	// Make a copy of the element to avoid mutating the one we were passed.
	el = el.Copy()

	sig, err := ctx.findSignature(el)
	if err != nil {
		return nil, err
	}

	cert, err := ctx.verifyCertificate(sig, true, false)
	if err != nil {
		return nil, err
	}

	return ctx.validateSignature(el, sig, cert)
}

// ValidateWithRootTrust does the same as Verify except it actually verifies the root CA is trusted as well
func (ctx *ValidationContext) ValidateWithRootTrust(el *etree.Element) ([]*etree.Element, error) {
	// Make a copy of the element to avoid mutating the one we were passed.
	el = el.Copy()

	sig, err := ctx.findSignature(el)
	if err != nil {
		return nil, err
	}

	cert, err := ctx.verifyCertificate(sig, true, true)
	if err != nil {
		return nil, err
	}

	return ctx.validateSignature(el, sig, cert)
}

// ValidateInsecure verifies that the passed element contains a valid enveloped signature
// without checking if certificate is the context's CertificateStore.
func (ctx *ValidationContext) ValidateInsecure(el *etree.Element) ([]*etree.Element, error) {
	// Make a copy of the element to avoid mutating the one we were passed.
	el = el.Copy()

	sig, err := ctx.findSignature(el)
	if err != nil {
		return nil, err
	}

	cert, err := ctx.verifyCertificate(sig, false, false)
	if err != nil {
		return nil, err
	}

	return ctx.validateSignature(el, sig, cert)
}
