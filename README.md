# xmldsig

[![Build Status](https://github.com/lafriks/go-xmldsig/actions/workflows/test.yml/badge.svg)](https://github.com/lafriks/go-xmldsig/actions/workflows/test.yml)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/lafriks/go-xmldsig)](https://pkg.go.dev/github.com/lafriks/go-xmldsig)

XML Digital Signatures implemented in pure Go.

Fork of [russellhaering/goxmldsig](https://github.com/russellhaering/goxmldsig)

## Supported Features

### Signature Algorithms

| Algorithm | URI |
|---|---|
| RSA PKCS#1 v1.5 (SHA-1, SHA-256, SHA-384, SHA-512) | `http://www.w3.org/2000/09/xmldsig#rsa-sha1` etc. |
| RSA-PSS | `http://www.w3.org/2007/05/xmldsig-more#rsa-pss` |
| ECDSA (P-256, P-384, P-521) | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` etc. |
| Ed25519 | `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` |
| HMAC-SHA1 | `http://www.w3.org/2000/09/xmldsig#hmac-sha1` |

### Digest Algorithms

| Algorithm | URI |
|---|---|
| SHA-1 | `http://www.w3.org/2000/09/xmldsig#sha1` |
| SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |
| SHA-384 | `http://www.w3.org/2001/04/xmldsig-more#sha384` |
| SHA-512 | `http://www.w3.org/2001/04/xmlenc#sha512` |

### Canonicalization Algorithms

| Algorithm | URI |
|---|---|
| Canonical XML 1.0 | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` |
| Canonical XML 1.0 with comments | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments` |
| Canonical XML 1.1 | `http://www.w3.org/2006/12/xml-c14n11` |
| Canonical XML 1.1 with comments | `http://www.w3.org/2006/12/xml-c14n11#WithComments` |
| Exclusive Canonical XML 1.0 | `http://www.w3.org/2001/10/xml-exc-c14n#` |
| Exclusive Canonical XML 1.0 with comments | `http://www.w3.org/2001/10/xml-exc-c14n#WithComments` |

### Transforms

| Transform | URI |
|---|---|
| Enveloped Signature | `http://www.w3.org/2000/09/xmldsig#enveloped-signature` |
| Base64 | `http://www.w3.org/2000/09/xmldsig#base64` |

### Reference URI Formats

| Format | Example |
|---|---|
| Bare ID reference | `#id1234` |
| XPointer bare-name | `#xpointer(id('id1234'))` |
| Full document | `#xpointer(/)` |
| Empty (whole document) | `""` |

### Structure

| Feature | Notes |
|---|---|
| Enveloped signatures | Signature embedded inside the signed element |
| Detached signatures | Signature alongside the signed element |
| `<Object>` with `<SignatureProperties>` | Signed metadata (e.g. signing timestamp) |
| Multiple references | Sign multiple elements in one signature |
| `crypto.Signer` interface | Delegate private key operations to HSMs or other backends |

### KeyInfo / Certificate Resolution

| Element | Support |
|---|---|
| `<X509Certificate>` | Full — parse and verify certificate chain |
| `<X509IssuerSerial>` | Resolve certificate by issuer DN and serial number |
| `<X509SKI>` | Resolve certificate by subject key identifier |
| `<X509SubjectName>` | Resolve certificate by subject distinguished name |

## Installation

Install `go-xmldsig` using `go get`:

```sh
go get github.com/lafriks/go-xmldsig/v2
```

## Usage

Include the [`types.Signature`](https://pkg.go.dev/github.com/russellhaering/goxmldsig/types#Signature) struct from this package in your application messages.

```go
import (
    sigtypes "github.com/russellhaering/goxmldsig/types"
)

type AppHdr struct {
    ...
    Signature *sigtypes.Signature
}
```

### Signing

It's possible to sign either whole XML document or only specific elements.

```go
package main

import (
    "github.com/beevik/etree"
    "github.com/lafriks/go-xmldsig/v2"
)

func main() {
    // Generate a key and self-signed certificate for signing
    randomKeyStore := xmldsig.RandomKeyStoreForTest()
    ctx := xmldsig.NewDefaultSigningContext(randomKeyStore)
    elementToSign := &etree.Element{
        Tag: "ExampleElement",
    }
    elementToSign.CreateAttr("ID", "id1234")

    // Sign the element
    signedElement, err := ctx.Sign(elementToSign)
    if err != nil {
        panic(err)
    }

    // Serialize the signed element. It is important not to modify the element
    // after it has been signed - even pretty-printing the XML will invalidate
    // the signature.
    doc := etree.NewDocument()
    doc.SetRoot(signedElement)
    str, err := doc.WriteToString()
    if err != nil {
        panic(err)
    }

    println(str)
}
```

### Signature Validation

```go
// Validate an element against a root certificate
func validate(root *x509.Certificate, el *etree.Element) {
    // Construct a signing context with one or more roots of trust.
    ctx := xmldsig.NewDefaultValidationContext(&xmldsig.MemoryX509CertificateStore{
        Roots: []*x509.Certificate{root},
    })

    // It is important to only use the returned validated element.
    // See: https://www.w3.org/TR/xmldsig-bestpractices/#check-what-is-signed
    validated, err := ctx.Validate(el)
    if err != nil {
        panic(err)
    }

    doc := etree.NewDocument()
    doc.SetRoot(validated[0])
    str, err := doc.WriteToString()
    if err != nil {
        panic(err)
    }

    println(str)
}
```
