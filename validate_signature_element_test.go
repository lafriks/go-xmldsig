package xmldsig

// Tests for the explicit-element entry point (follow-up to the traversal
// fixes): ValidateSignatureElement lets a caller hand over an already-located
// Signature element, skipping the search — and its budget — entirely.
// signedLargeDoc lives in validate_traversal_test.go.

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func elementString(t *testing.T, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	s, err := doc.WriteToString()
	require.NoError(t, err)
	return s
}

// TestValidateSignatureElement: the caller locates the Signature (here:
// trivially, as the last child), hands it over, and validation succeeds with
// the search — and its budget — never involved. The passed tree must not be
// mutated.
func TestValidateSignatureElement(t *testing.T) {
	signed, vctx := signedLargeDoc(t, 2000)
	vctx.MaxTraversalElements = 1 // would make any deep search impossible

	children := signed.ChildElements()
	sigEl := children[len(children)-1]

	before := elementString(t, signed)

	validated, err := vctx.ValidateSignatureElement(signed, sigEl)
	require.NoError(t, err)
	require.NotEmpty(t, validated)

	require.Equal(t, before, elementString(t, signed),
		"ValidateSignatureElement must not mutate the passed tree")
}

// TestValidateSignatureElementRejectsWrongElement: the explicit API must not
// become a validation bypass — foreign elements, the root itself, and
// non-signature children are all rejected.
func TestValidateSignatureElementRejectsWrongElement(t *testing.T) {
	signed, vctx := signedLargeDoc(t, 10)

	// An element from a different tree.
	foreign := etree.NewElement("Signature")
	_, err := vctx.ValidateSignatureElement(signed, foreign)
	require.ErrorIs(t, err, ErrMissingSignature)

	// The root itself.
	_, err = vctx.ValidateSignatureElement(signed, signed)
	require.Error(t, err)

	// A non-signature child.
	_, err = vctx.ValidateSignatureElement(signed, signed.ChildElements()[0])
	require.ErrorIs(t, err, ErrMissingSignature)
}
