package xmldsig

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"github.com/lafriks/go-xmldsig/etreeutils"

	"github.com/beevik/etree"
)

var whiteSpace = regexp.MustCompile(`\\s+`)

var (
	// ErrMissingSignature indicates that no enveloped signature was found referencing
	// the top level element passed for signature verification.
	ErrMissingSignature = errors.New("missing signature referencing the top-level element")
	ErrInvalidSignature = errors.New("invalid signature")
)

type KeyInfoCertificateResolver func(sig *etree.Element) (*x509.Certificate, error)

type ValidationContext struct {
	CertificateStore    X509CertificateStore
	IdAttribute         string
	Clock               Clock
	CertificateResolver KeyInfoCertificateResolver
}

func NewDefaultValidationContext(certificateStore X509CertificateStore) *ValidationContext {
	return &ValidationContext{
		CertificateStore: certificateStore,
		IdAttribute:      DefaultIdAttr,
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
		el.RemoveChild(childElement)
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
		case EnvelopedSignatureAltorithmId:
			if !removeElementAtPath(el, signaturePath) {
				return nil, errors.New("error applying canonicalization transform: Signature not found")
			}

		case CanonicalXML10ExclusiveAlgorithmId:
			var prefixList string
			if transform.InclusiveNamespaces != nil {
				prefixList = transform.InclusiveNamespaces.PrefixList
			}

			canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList)

		case CanonicalXML10ExclusiveWithCommentsAlgorithmId:
			var prefixList string
			if transform.InclusiveNamespaces != nil {
				prefixList = transform.InclusiveNamespaces.PrefixList
			}

			canonicalizer = MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList)

		case CanonicalXML11AlgorithmId:
			canonicalizer = MakeC14N11Canonicalizer()

		case CanonicalXML11WithCommentsAlgorithmId:
			canonicalizer = MakeC14N11WithCommentsCanonicalizer()

		case CanonicalXML10RecAlgorithmId:
			canonicalizer = MakeC14N10RecCanonicalizer()

		case CanonicalXML10WithCommentsAlgorithmId:
			canonicalizer = MakeC14N10WithCommentsCanonicalizer()

		default:
			return nil, errors.New("unknown transform algorithm: " + algo)
		}
	}

	if canonicalizer == nil {
		canonicalizer = MakeNullCanonicalizer()
	}

	return canonicalizer, nil
}

func (ctx *ValidationContext) digest(el *etree.Element, digestAlgorithmId string, canonicalizer Canonicalizer) ([]byte, error) {
	canonical, err := canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	digestAlgorithm, ok := digestAlgorithmsByIdentifier[digestAlgorithmId]
	if !ok {
		return nil, errors.New("unknown digest algorithm: " + digestAlgorithmId)
	}

	hash := digestAlgorithm.New()
	_, err = hash.Write(canonical)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (ctx *ValidationContext) verifySignedInfo(sig *Signature, signatureMethodId string, cert *x509.Certificate, decodedSignature []byte) error {
	signatureElement := sig.UnderlyingElement()

	nsCtx, err := etreeutils.NSBuildParentContext(signatureElement)
	if err != nil {
		return err
	}

	signedInfo, err := etreeutils.NSFindOneChildCtx(nsCtx, signatureElement, Namespace, SignedInfoTag)
	if err != nil {
		return err
	}

	if signedInfo == nil {
		return errors.New("missing SignedInfo")
	}

	// Canonicalize the xml
	canonical, err := canonicalSerialize(signedInfo)
	if err != nil {
		return err
	}

	algo, ok := x509SignatureAlgorithmByIdentifier[signatureMethodId]
	if !ok {
		return errors.New("unknown signature method: " + signatureMethodId)
	}

	err = cert.CheckSignature(algo, canonical, decodedSignature)
	if err != nil {
		return err
	}

	return nil
}

func (ctx *ValidationContext) validateSignature(el *etree.Element, sig *Signature, cert *x509.Certificate) error {
	// Find the first reference which references the top-level element
	for _, ref := range sig.SignedInfo.References {
		referencedEl := el
		if ref.URI != "" &&
			(ref.URI[0] != '#' || referencedEl.SelectAttrValue(ctx.IdAttribute, "") != ref.URI[1:]) {
			var rawPath string

			switch ref.URI[0] {
			case '/':
				rawPath = ref.URI
			case '#':
				rawPath = "//*[@" + ctx.IdAttribute + "='" + ref.URI[1:] + "']"
			default:
				return errors.New("unsupported reference URI: " + ref.URI)
			}
			path, err := etree.CompilePath(rawPath)
			if err != nil {
				return err
			}
			referencedEl = el.FindElementPath(path)
			if referencedEl == nil {
				return errors.New("error implementing etree: " + rawPath)
			}
		}

		// Perform all transformations listed in the 'SignedInfo'
		// Basically, this means removing the 'SignedInfo'
		canonicalizer, err := ctx.transform(referencedEl, sig, &ref)
		if err != nil {
			return err
		}

		transformedEl := referencedEl

		if alg := canonicalizer.Algorithm(); alg == CanonicalXML11AlgorithmId || alg == CanonicalXML11WithCommentsAlgorithmId {
			// When using xml-c14n11 (ie, non-exclusive canonicalization) the canonical form
			// of the element must declare all namespaces that are in scope at it's final
			// enveloped location in the document. In order to do that, we're going to construct
			// a series of cascading NSContexts to capture namespace declarations:

			// First get the context surrounding the element we are signing.
			rootNSCtx, err := etreeutils.NSBuildParentContext(referencedEl)
			if err != nil {
				return err
			}

			// Then capture any declarations on the element itself.
			digestNSCtx, err := rootNSCtx.SubContext(referencedEl)
			if err != nil {
				return err
			}

			// Finally detatch the element in order to capture all of the namespace
			// declarations in the scope we've constructed.
			transformedEl, err = etreeutils.NSDetatch(digestNSCtx, referencedEl)
			if err != nil {
				return err
			}
		}

		digestAlgorithm := ref.DigestAlgo.Algorithm

		// Digest the transformed XML and compare it to the 'DigestValue' from the 'SignedInfo'
		digest, err := ctx.digest(transformedEl, digestAlgorithm, canonicalizer)
		if err != nil {
			return err
		}

		decodedDigestValue, err := base64.StdEncoding.DecodeString(ref.DigestValue)
		if err != nil {
			return err
		}

		if !bytes.Equal(digest, decodedDigestValue) {
			return errors.New("digest is not valid for '" + ref.URI + "'")
		}
	}

	if sig.SignatureValue == nil {
		return errors.New("missing signature value")
	}

	// Decode the 'SignatureValue' so we can compare against it
	decodedSignature, err := base64.StdEncoding.DecodeString(sig.SignatureValue.Data)
	if err != nil {
		return fmt.Errorf("could not decode signature: %w", err)
	}

	// Actually verify the 'SignedInfo' was signed by a trusted source
	signatureMethod := sig.SignedInfo.SignatureMethod.Algorithm
	err = ctx.verifySignedInfo(sig, signatureMethod, cert, decodedSignature)
	if err != nil {
		return err
	}

	return nil
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
	children := signatureEl.ChildElements()

	childCounts := map[string]int{}
	for _, child := range children {
		childCounts[child.Tag]++
	}

	validateCount := childCounts[SignedInfoTag] == 1 && childCounts[KeyInfoTag] <= 1 && childCounts[SignatureValueTag] == 1
	if !validateCount {
		return ErrInvalidSignature
	}
	return nil
}

// findSignature searches for a Signature element referencing the passed root element.
func (ctx *ValidationContext) findSignature(root *etree.Element) (*Signature, error) {
	idAttrEl := root.SelectAttr(ctx.IdAttribute)
	idAttr := ""
	if idAttrEl != nil {
		idAttr = idAttrEl.Value
	}

	var sig *Signature
	var lsig *Signature

	// Traverse the tree looking for a Signature element
	err := etreeutils.NSFindIterate(root, Namespace, SignatureTag, func(ctx etreeutils.NSContext, signatureEl *etree.Element) error {
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
				case CanonicalXML10ExclusiveAlgorithmId, CanonicalXML10ExclusiveWithCommentsAlgorithmId:
					detachedSignedInfo := signedInfo.Copy()
					err := etreeutils.TransformExcC14nWithContext(ctx, detachedSignedInfo, "", alg == CanonicalXML10ExclusiveWithCommentsAlgorithmId)
					if err != nil {
						return err
					}

					// NOTE: TransformExcC14n transforms the element in-place,
					// while canonicalPrep isn't meant to. Once we standardize
					// this behavior we can drop this, as well as the adding and
					// removing of elements below.
					canonicalSignedInfo = detachedSignedInfo

				case CanonicalXML11AlgorithmId, CanonicalXML11WithCommentsAlgorithmId:
					detachedSignedInfo, err := etreeutils.NSDetatch(ctx, signedInfo)
					if err != nil {
						return err
					}
					canonicalSignedInfo = canonicalPrep(detachedSignedInfo, map[string]struct{}{}, true, alg == CanonicalXML11WithCommentsAlgorithmId)

				case CanonicalXML10RecAlgorithmId, CanonicalXML10WithCommentsAlgorithmId:
					canonicalSignedInfo = canonicalPrep(signedInfo, map[string]struct{}{}, true, alg == CanonicalXML10WithCommentsAlgorithmId)

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
			if ref.URI == "" || ref.URI[1:] == idAttr {
				sig = _sig
				return etreeutils.ErrTraversalHalted
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
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
		if len(sig.KeyInfo.X509Data.X509Certificates) != 0 && sig.KeyInfo.X509Data.X509Certificates[0].Data != "" {
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
		opts := x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}

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
func (ctx *ValidationContext) Validate(el *etree.Element) error {
	// Make a copy of the element to avoid mutating the one we were passed.
	el = el.Copy()

	sig, err := ctx.findSignature(el)
	if err != nil {
		return err
	}

	cert, err := ctx.verifyCertificate(sig, true, false)
	if err != nil {
		return err
	}

	return ctx.validateSignature(el, sig, cert)
}

// ValidateWithRootTrust does the same as Verify except it actually verifies the root CA is trusted as well
func (ctx *ValidationContext) ValidateWithRootTrust(el *etree.Element) error {
	// Make a copy of the element to avoid mutating the one we were passed.
	el = el.Copy()

	sig, err := ctx.findSignature(el)
	if err != nil {
		return err
	}

	cert, err := ctx.verifyCertificate(sig, true, true)
	if err != nil {
		return err
	}

	return ctx.validateSignature(el, sig, cert)
}

// ValidateInsecure verifies that the passed element contains a valid enveloped signature
// without checking if certificate is the context's CertificateStore.
func (ctx *ValidationContext) ValidateInsecure(el *etree.Element) error {
	// Make a copy of the element to avoid mutating the one we were passed.
	el = el.Copy()

	sig, err := ctx.findSignature(el)
	if err != nil {
		return err
	}

	cert, err := ctx.verifyCertificate(sig, false, false)
	if err != nil {
		return err
	}

	return ctx.validateSignature(el, sig, cert)
}
