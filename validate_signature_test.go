package xmldsig

// These tests cover ValidateSignature, the explicit-element entry point: the
// caller locates the enveloped Signature element itself, so the signature
// search — and its traversal budget — is skipped entirely, while the
// acceptance rule, trust checks and digest verification stay identical to
// Validate. They reuse the signedLargeDoc/nestedSignedDoc helpers from
// validate_traversal_test.go.

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// lastChildSignature returns root's last child element, asserting it is the
// Signature (where SignEnveloped puts it).
func lastChildSignature(t *testing.T, root *etree.Element) *etree.Element {
	t.Helper()
	children := root.ChildElements()
	require.NotEmpty(t, children)
	sig := children[len(children)-1]
	require.Equal(t, SignatureTag, sig.Tag)
	return sig
}

// serializeTree renders a detached copy of el, for byte-level before/after
// comparison (copying first so the original is never reparented into a
// Document).
func serializeTree(t *testing.T, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	s, err := doc.WriteToString()
	require.NoError(t, err)
	return s
}

// TestValidateSignature pins the API's defining property: validation of a
// caller-located signature succeeds even when the budget would make the
// search impossible, and the caller's tree is byte-identical afterwards (the
// canonical-SignedInfo swap happens only in the defensive copy).
func TestValidateSignature(t *testing.T) {
	signed, vctx := signedLargeDoc(t, 2000)
	vctx.MaxTraversalElements = 1

	sig := lastChildSignature(t, signed)
	before := serializeTree(t, signed)

	validated, err := vctx.ValidateSignature(signed, sig)
	require.NoError(t, err)
	require.NotEmpty(t, validated)

	require.Equal(t, before, serializeTree(t, signed),
		"ValidateSignature must not mutate the caller's tree")
}

// TestValidateSignatureRejectsWrongElement pins the guards that keep the API
// from becoming a validation bypass: the caller chooses which signature to
// validate, never whether the rules apply.
func TestValidateSignatureRejectsWrongElement(t *testing.T) {
	signed, vctx := signedLargeDoc(t, 5)

	// A foreign element that is not part of root's tree.
	foreign := etree.NewElement(SignatureTag)
	_, err := vctx.ValidateSignature(signed, foreign)
	require.ErrorIs(t, err, ErrMissingSignature)

	// The root itself cannot be its own enveloped signature.
	_, err = vctx.ValidateSignature(signed, signed)
	require.Error(t, err)

	// A child of the root that is not a Signature element.
	notSig := signed.ChildElements()[0]
	require.NotEqual(t, SignatureTag, notSig.Tag)
	_, err = vctx.ValidateSignature(signed, notSig)
	require.ErrorIs(t, err, ErrMissingSignature)

	// Nil elements.
	_, err = vctx.ValidateSignature(signed, nil)
	require.Error(t, err)
	_, err = vctx.ValidateSignature(nil, lastChildSignature(t, signed))
	require.Error(t, err)
}

// TestValidateSignatureAcceptanceRule pins parity with the search's
// acceptance rule: an ID'd root requires the signature to reference it, while
// an id-less root accepts a non-root-referencing signature (the search's
// last-signature fallback).
func TestValidateSignatureAcceptanceRule(t *testing.T) {
	// ID'd root, signature referencing a different id: rejected before any
	// trust or digest work.
	signed, vctx := signedLargeDoc(t, 3)
	sig := lastChildSignature(t, signed)
	signed.CreateAttr(DefaultIDAttr, "some-other-id")
	_, err := vctx.ValidateSignature(signed, sig)
	require.ErrorIs(t, err, ErrMissingSignature)

	// Id-less root: the signature inside the nested signed document does not
	// reference the outer envelope, but is accepted via the fallback and then
	// fully digest-verified.
	outer, vctx := nestedSignedDoc(t, 3)
	vctx.MaxTraversalElements = 1 // irrelevant: no search happens
	innerChildren := outer.ChildElements()
	inner := innerChildren[len(innerChildren)-1]
	nestedSig := lastChildSignature(t, inner)

	validated, err := vctx.ValidateSignature(outer, nestedSig)
	require.NoError(t, err)
	require.NotEmpty(t, validated)
}
