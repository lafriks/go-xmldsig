package xmldsig

// These tests document and guard the large-document signature-search fixes:
//
//   1. A children-first fast path locates enveloped signatures that are direct
//      children of the root (the standard XMLDSig shape; mandated by profiles
//      such as ETSI TS 119 612 trusted lists) WITHOUT consuming the traversal
//      budget. Previously, a document with more than ~1000 elements whose
//      Signature sat at the END of the root (where SignEnveloped itself puts
//      it!) failed with "traversal limit reached" before the search ever
//      reached the signature — every real EU trusted list hit this.
//   2. ValidationContext.MaxTraversalElements makes the deep-search budget
//      configurable (0 = default 1000, negative = unlimited) for documents
//      whose signature is genuinely nested.
//
// They also roundtrip-validate SignEnveloped's own output, which doubles as
// the regression suite for the enveloped-transform removal fix (signature
// removed by its identity-mapped child slot rather than the token's cached
// index — see docs/enveloped-transform-removal-fix.md).

import (
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/lafriks/go-xmldsig/v2/etreeutils"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// signedLargeDoc builds a root with fillerChildren*2 descendant elements and
// an enveloped signature appended as the LAST child — the exact shape of an
// ETSI trusted list (huge document, ds:Signature as the final child of the
// root) — and a validation context trusting the signing certificate.
func signedLargeDoc(t *testing.T, fillerChildren int) (*etree.Element, *ValidationContext) {
	t.Helper()

	root := etree.NewElement("TrustServiceStatusList")
	root.CreateAttr(DefaultIDAttr, "rootid")
	for i := 0; i < fillerChildren; i++ {
		entry := root.CreateElement("Entry")
		entry.CreateElement("Name").SetText(fmt.Sprintf("entry-%d", i))
	}

	ks := RandomKeyStoreForTest()
	sctx := NewDefaultSigningContext(ks)
	// Trusted lists (and SAML) sign with EXCLUSIVE canonicalization; the
	// library default is C14N 1.1, whose NSDetatch-based digesting is
	// sensitive to the surrounding namespace context. Exclusive C14N is both
	// what the documents this PR targets actually use and roundtrip-stable
	// for a synthetic unprefixed root.
	sctx.Canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := sctx.SignEnveloped(root)
	require.NoError(t, err)

	// Precondition for the whole scenario: the signature is the LAST child.
	children := signed.ChildElements()
	require.Equal(t, SignatureTag, children[len(children)-1].Tag,
		"SignEnveloped must append the signature as the last child")

	_, certDER, err := ks.GetKeyPair()
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	vctx := NewDefaultValidationContext(&MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	return signed, vctx
}

// TestValidateLargeDocumentSignatureAsLastChild is the headline regression
// test: ~4000 elements before the root-level signature. Before the
// children-first fast path, the budgeted depth-first search exhausted its
// 1000-element budget on the filler subtrees and failed with
// etreeutils.ErrTraversalLimit without ever reaching the signature.
func TestValidateLargeDocumentSignatureAsLastChild(t *testing.T) {
	signed, vctx := signedLargeDoc(t, 2000)

	validated, err := vctx.Validate(signed)
	require.NoError(t, err,
		"a root-level enveloped signature must be found regardless of document size")
	require.NotEmpty(t, validated)
}

// TestFastPathIgnoresTraversalBudget pins the fast path's defining property:
// a root-level signature is found even with an absurdly small budget, because
// scanning the root's direct children is not a traversal.
func TestFastPathIgnoresTraversalBudget(t *testing.T) {
	signed, vctx := signedLargeDoc(t, 2000)
	vctx.MaxTraversalElements = 1

	validated, err := vctx.Validate(signed)
	require.NoError(t, err)
	require.NotEmpty(t, validated)
}

// nestedSignedDoc wraps a small signed document inside an unsigned envelope
// padded with filler subtrees, so the signature is NOT a direct child of the
// validated root and only the budgeted deep search can find it.
func nestedSignedDoc(t *testing.T, fillerChildren int) (*etree.Element, *ValidationContext) {
	t.Helper()

	inner, vctx := signedLargeDoc(t, 0)

	outer := etree.NewElement("Envelope") // deliberately no ID attribute
	for i := 0; i < fillerChildren; i++ {
		entry := outer.CreateElement("Filler")
		entry.CreateElement("Name").SetText(fmt.Sprintf("filler-%d", i))
	}
	outer.AddChild(inner)
	return outer, vctx
}

// TestMaxTraversalElements exercises the configurable deep-search budget on a
// nested signature behind ~4000 filler elements: the default budget fails
// (unchanged upstream behaviour), a raised budget succeeds, unlimited
// succeeds, and an explicitly small budget fails.
func TestMaxTraversalElements(t *testing.T) {
	outer, vctx := nestedSignedDoc(t, 2000)

	// Default budget (MaxTraversalElements == 0 → 1000): the deep search runs
	// out before reaching the nested signature.
	_, err := vctx.Validate(outer)
	require.ErrorIs(t, err, etreeutils.ErrTraversalLimit,
		"default budget must still bound a genuinely deep search (DoS guard unchanged)")

	// Raised budget: enough to walk the fillers.
	vctx.MaxTraversalElements = 100_000
	validated, err := vctx.Validate(outer)
	require.NoError(t, err)
	require.NotEmpty(t, validated)

	// Unlimited (negative).
	vctx.MaxTraversalElements = -1
	_, err = vctx.Validate(outer)
	require.NoError(t, err)

	// Explicit small budget.
	vctx.MaxTraversalElements = 50
	_, err = vctx.Validate(outer)
	require.ErrorIs(t, err, etreeutils.ErrTraversalLimit)
}

// TestValidateSmallDocumentStillWorks guards against regressions in the
// ordinary SAML-sized case the library was originally built for.
func TestValidateSmallDocumentStillWorks(t *testing.T) {
	signed, vctx := signedLargeDoc(t, 3)

	validated, err := vctx.Validate(signed)
	require.NoError(t, err)
	require.NotEmpty(t, validated)
}
