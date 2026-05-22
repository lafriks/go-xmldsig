package xmldsig

import (
	"encoding/base64"
	"maps"
	"sort"

	"github.com/lafriks/go-xmldsig/v2/etreeutils"

	"github.com/beevik/etree"
)

// Canonicalizer is an implementation of a canonicalization algorithm.
type Canonicalizer interface {
	Canonicalize(el *etree.Element) ([]byte, error)
	Algorithm() AlgorithmID
}

type base64Canonicalizer struct{}

// MakeBase64Canonicalizer constructs a transform that strips whitespace from
// an element's text content and base64-decodes it, per XMLDSig Core §6.6.2.
// Use it when a Reference points to an element whose text is base64-encoded
// binary data (e.g. X509Certificate, BinarySecurityToken).
func MakeBase64Canonicalizer() Canonicalizer {
	return &base64Canonicalizer{}
}

func (c *base64Canonicalizer) Algorithm() AlgorithmID {
	return Base64TransformAlgorithmID
}

func (c *base64Canonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	return base64.StdEncoding.DecodeString(whiteSpace.ReplaceAllString(el.Text(), ""))
}

type NullCanonicalizer struct{}

func MakeNullCanonicalizer() Canonicalizer {
	return &NullCanonicalizer{}
}

func (c *NullCanonicalizer) Algorithm() AlgorithmID {
	return AlgorithmID("NULL")
}

func (c *NullCanonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	return canonicalSerialize(canonicalPrep(el, false, true))
}

type c14N10ExclusiveCanonicalizer struct {
	prefixList string
	comments   bool
}

// MakeC14N10ExclusiveCanonicalizerWithPrefixList constructs an exclusive Canonicalizer
// from a PrefixList in NMTOKENS format (a white space separated list).
func MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList string) Canonicalizer {
	return &c14N10ExclusiveCanonicalizer{
		prefixList: prefixList,
		comments:   false,
	}
}

// MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList constructs an exclusive Canonicalizer
// from a PrefixList in NMTOKENS format (a white space separated list).
func MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList string) Canonicalizer {
	return &c14N10ExclusiveCanonicalizer{
		prefixList: prefixList,
		comments:   true,
	}
}

// Canonicalize transforms the input Element into a serialized XML document in canonical form.
func (c *c14N10ExclusiveCanonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}

	el = el.Copy()
	if err = etreeutils.TransformExcC14nWithContext(ctx, el, c.prefixList, c.comments); err != nil {
		return nil, err
	}

	return canonicalSerialize(el)
}

func (c *c14N10ExclusiveCanonicalizer) Algorithm() AlgorithmID {
	if c.comments {
		return CanonicalXML10ExclusiveWithCommentsAlgorithmID
	}
	return CanonicalXML10ExclusiveAlgorithmID
}

type c14N11Canonicalizer struct {
	comments bool
}

// MakeC14N11Canonicalizer constructs an inclusive canonicalizer.
func MakeC14N11Canonicalizer() Canonicalizer {
	return &c14N11Canonicalizer{
		comments: false,
	}
}

// MakeC14N11WithCommentsCanonicalizer constructs an inclusive canonicalizer.
func MakeC14N11WithCommentsCanonicalizer() Canonicalizer {
	return &c14N11Canonicalizer{
		comments: true,
	}
}

// Canonicalize transforms the input Element into a serialized XML document in canonical form.
func (c *c14N11Canonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	parentNamespaceAttributes, parentXmlAttributes := getParentNamespaceAndXmlAttributes(el)
	elCopy := el.Copy()
	enhanceNamespaceAttributes(elCopy, parentNamespaceAttributes, parentXmlAttributes)
	return canonicalSerialize(canonicalPrep(elCopy, true, c.comments))
}

func (c *c14N11Canonicalizer) Algorithm() AlgorithmID {
	if c.comments {
		return CanonicalXML11WithCommentsAlgorithmID
	}
	return CanonicalXML11AlgorithmID
}

type c14N10Canonicalizer struct {
	comments bool
}

// MakeC14N10Canonicalizer constructs an inclusive canonicalizer.
func MakeC14N10Canonicalizer() Canonicalizer {
	return &c14N10Canonicalizer{
		comments: false,
	}
}

// MakeC14N10WithCommentsCanonicalizer constructs an inclusive canonicalizer.
func MakeC14N10WithCommentsCanonicalizer() Canonicalizer {
	return &c14N10Canonicalizer{
		comments: true,
	}
}

// Canonicalize transforms the input Element into a serialized XML document in canonical form.
func (c *c14N10Canonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	parentNamespaceAttributes, parentXmlAttributes := getParentNamespaceAndXmlAttributes(el)
	elCopy := el.Copy()
	enhanceNamespaceAttributes(elCopy, parentNamespaceAttributes, parentXmlAttributes)
	return canonicalSerialize(canonicalPrep(elCopy, true, c.comments))
}

func (c *c14N10Canonicalizer) Algorithm() AlgorithmID {
	if c.comments {
		return CanonicalXML10WithCommentsAlgorithmID
	}
	return CanonicalXML10AlgorithmID
}

const nsSpace = "xmlns"

// canonicalPrep accepts an *etree.Element and transforms it into one which is ready
// for serialization into inclusive canonical form. Specifically this
// entails:
//
// 1. Stripping re-declarations of namespaces
// 2. Sorting attributes into canonical order
//
// Inclusive canonicalization does not strip unused namespaces.
//
// TODO(russell_h): This is very similar to excCanonicalPrep - perhaps they should
// be unified into one parameterized function?
func canonicalPrep(el *etree.Element, strip bool, comments bool) *etree.Element {
	return canonicalPrepInner(el, etreeutils.NewDefaultNSContext(), make(map[string]string), strip, comments)
}

func canonicalPrepInner(el *etree.Element, parentCtx etreeutils.NSContext, seenSoFar map[string]string, strip bool, comments bool) *etree.Element {
	_seenSoFar := make(map[string]string)
	maps.Copy(_seenSoFar, seenSoFar)

	ne := el.Copy()
	ctx, err := parentCtx.SubContext(ne)
	if err != nil {
		ctx = parentCtx
	}
	sort.Sort(etreeutils.NewSortedAttrs(ctx, ne.Attr))
	n := 0
	for _, attr := range ne.Attr {
		if attr.Space != nsSpace && (attr.Space != "" || attr.Key != nsSpace) {
			ne.Attr[n] = attr
			n++
			continue
		}

		if attr.Space == nsSpace {
			key := attr.Space + ":" + attr.Key
			if uri, seen := _seenSoFar[key]; !seen || attr.Value != uri {
				ne.Attr[n] = attr
				n++
				_seenSoFar[key] = attr.Value
			}
		} else {
			if uri, seen := _seenSoFar[nsSpace]; (!seen && attr.Value != "") || attr.Value != uri {
				ne.Attr[n] = attr
				n++
				_seenSoFar[nsSpace] = attr.Value
			}
		}
	}
	ne.Attr = ne.Attr[:n]

	if !comments {
		c := 0
		for c < len(ne.Child) {
			if _, ok := ne.Child[c].(*etree.Comment); ok {
				ne.RemoveChildAt(c)
			} else {
				c++
			}
		}
	}

	for i, token := range ne.Child {
		childElement, ok := token.(*etree.Element)
		if ok {
			ne.Child[i] = canonicalPrepInner(childElement, ctx, _seenSoFar, strip, comments)
		}
	}

	return ne
}

func canonicalSerialize(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}

	return doc.WriteToBytes()
}

func getParentNamespaceAndXmlAttributes(el *etree.Element) (map[string]string, map[string]string) {
	namespaceMap := make(map[string]string, 23)
	xmlMap := make(map[string]string, 5)
	parents := make([]*etree.Element, 0, 23)
	n1 := el.Parent()
	if n1 == nil {
		return namespaceMap, xmlMap
	}
	parent := n1
	for parent != nil {
		parents = append(parents, parent)
		parent = parent.Parent()
	}
	for i := len(parents) - 1; i > -1; i-- {
		elementPos := parents[i]
		for _, attr := range elementPos.Attr {
			if attr.Space == "xmlns" && (attr.Key != "xml" || attr.Value != "http://www.w3.org/XML/1998/namespace") {
				namespaceMap[attr.Key] = attr.Value
			} else if attr.Space == "" && attr.Key == "xmlns" {
				namespaceMap[attr.Key] = attr.Value
			} else if attr.Space == "xml" {
				xmlMap[attr.Key] = attr.Value
			}
		}
	}
	return namespaceMap, xmlMap
}

func enhanceNamespaceAttributes(el *etree.Element, parentNamespaces map[string]string, parentXmlAttributes map[string]string) {
	for prefix, uri := range parentNamespaces {
		if prefix == "xmlns" {
			el.CreateAttr("xmlns", uri)
		} else {
			el.CreateAttr("xmlns:"+prefix, uri)
		}
	}
	for attr, value := range parentXmlAttributes {
		el.CreateAttr("xml:"+attr, value)
	}
}
