package etreeutils

import (
	"github.com/beevik/etree"
)

// SortedAttrs provides sorting capabilities, compatible with XML C14N, on top
// of an []etree.Attr
type SortedAttrs struct {
	ctx   NSContext
	attrs []etree.Attr
}

// NewSortedAttrs returns a new SortedAttrs instance.
func NewSortedAttrs(ctx NSContext, attrs []etree.Attr) *SortedAttrs {
	return &SortedAttrs{
		ctx:   ctx,
		attrs: attrs,
	}
}

func (a *SortedAttrs) Len() int {
	return len(a.attrs)
}

func (a *SortedAttrs) Swap(i, j int) {
	a.attrs[i], a.attrs[j] = a.attrs[j], a.attrs[i]
}

func (a *SortedAttrs) Less(i, j int) bool {
	// This is the best reference I've found on sort order:
	// http://dst.lbl.gov/~ksb/Scratch/XMLC14N.html

	// If attr j is a default namespace declaration, attr i may
	// not be strictly "less" than it.
	if a.attrs[j].Space == defaultPrefix && a.attrs[j].Key == xmlnsPrefix {
		return false
	}

	// Otherwise, if attr i is a default namespace declaration, it
	// must be less than anything else.
	if a.attrs[i].Space == defaultPrefix && a.attrs[i].Key == xmlnsPrefix {
		return true
	}

	// Next, namespace prefix declarations, sorted by prefix, come before
	// anythign else.
	if a.attrs[i].Space == xmlnsPrefix {
		if a.attrs[j].Space == xmlnsPrefix {
			return a.attrs[i].Key < a.attrs[j].Key
		}
		return true
	}

	if a.attrs[j].Space == xmlnsPrefix {
		return false
	}

	// Then come unprefixed attributes, sorted by key.
	if a.attrs[i].Space == defaultPrefix {
		if a.attrs[j].Space == defaultPrefix {
			return a.attrs[i].Key < a.attrs[j].Key
		}
		return true
	}

	if a.attrs[j].Space == defaultPrefix {
		return false
	}

	// Attributes in the same namespace should be sorted by key.
	if a.attrs[i].Space == a.attrs[j].Space {
		return a.attrs[i].Key < a.attrs[j].Key
	}

	// Finally, attributes in different namespaces should be sorted by the
	// actual namespace (_not_ the prefix).
	iNS, err := a.ctx.LookupPrefix(a.attrs[i].Space)
	if err != nil {
		iNS = a.attrs[i].Space
	}
	jNS, err := a.ctx.LookupPrefix(a.attrs[j].Space)
	if err != nil {
		jNS = a.attrs[j].Space
	}

	return iNS < jNS
}
