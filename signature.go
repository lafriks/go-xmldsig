package xmldsig

import (
	"encoding/xml"

	"github.com/beevik/etree"
)

type InclusiveNamespaces struct {
	XMLName    xml.Name `xml:"http://www.w3.org/2001/10/xml-exc-c14n# InclusiveNamespaces"`
	PrefixList string   `xml:"PrefixList,attr"`
}

type Transform struct {
	XMLName             xml.Name             `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
	Algorithm           string               `xml:"Algorithm,attr"`
	InclusiveNamespaces *InclusiveNamespaces `xml:"InclusiveNamespaces"`
}

type Transforms struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transforms []Transform `xml:"Transform"`
}

type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type Reference struct {
	XMLName     xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI         string       `xml:"URI,attr"`
	DigestValue string       `xml:"DigestValue"`
	DigestAlgo  DigestMethod `xml:"DigestMethod"`
	Transforms  Transforms   `xml:"Transforms"`
}

type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// MGFAlgorithm represents the MaskGenerationFunction element within RSAPSSParams.
type MGFAlgorithm struct {
	Algorithm    string       `xml:"Algorithm,attr"`
	DigestMethod DigestMethod `xml:"DigestMethod"`
}

// RSAPSSParams holds the RSA-PSS parameters carried as child elements of
// <SignatureMethod> per RFC 6931 §2.3.9.
type RSAPSSParams struct {
	XMLName                xml.Name     `xml:"http://www.w3.org/2007/05/xmldsig-more# RSAPSSParams"`
	DigestMethod           DigestMethod `xml:"DigestMethod"`
	MaskGenerationFunction MGFAlgorithm `xml:"MaskGenerationFunction"`
	SaltLength             int          `xml:"SaltLength"`
	TrailerField           int          `xml:"TrailerField"`
}

type SignatureMethod struct {
	XMLName      xml.Name      `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm    string        `xml:"Algorithm,attr"`
	RSAPSSParams *RSAPSSParams `xml:"RSAPSSParams"`
}

type SignedInfo struct {
	XMLName                xml.Name               `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
	References             []Reference            `xml:"Reference"`
}

type SignatureValue struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	Data    string   `xml:",chardata"`
}

type KeyInfo struct {
	XMLName  xml.Name  `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	KeyName  string    `xml:"KeyName"`
	X509Data *X509Data `xml:"X509Data"`
}

// X509IssuerSerial identifies a certificate by its issuer distinguished name
// and serial number per XMLDSig §4.4.4.
type X509IssuerSerial struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509IssuerSerial"`
	IssuerName   string   `xml:"X509IssuerName"`
	SerialNumber string   `xml:"X509SerialNumber"`
}

type X509Data struct {
	XMLName          xml.Name           `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificates []X509Certificate  `xml:"X509Certificate"`
	IssuerSerials    []X509IssuerSerial `xml:"X509IssuerSerial"`
	// SKIs holds base64-encoded Subject Key Identifier values.
	SKIs []string `xml:"X509SKI"`
	// SubjectNames holds X.500 distinguished name strings.
	SubjectNames []string `xml:"X509SubjectName"`
	// CRLs holds base64-encoded DER certificate revocation lists.
	CRLs []string `xml:"X509CRL"`
}

type X509Certificate struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	Data    string   `xml:",chardata"`
}

// Object is an optional container for arbitrary content that can be included
// and referenced within a Signature per XMLDSig Core §4.5.
type Object struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Object"`
	ID       string   `xml:"Id,attr,omitempty"`
	MimeType string   `xml:"MimeType,attr,omitempty"`
	Encoding string   `xml:"Encoding,attr,omitempty"`
	InnerXML string   `xml:",innerxml"`
}

// SignatureProperty holds a single property about the signing act, such as a
// timestamp or signing location. It must target a Signature element via URI.
type SignatureProperty struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureProperty"`
	ID       string   `xml:"Id,attr,omitempty"`
	Target   string   `xml:"Target,attr"`
	InnerXML string   `xml:",innerxml"`
}

// SignatureProperties is a container for SignatureProperty elements, typically
// placed inside a signed Object per XMLDSig Core §4.6.
type SignatureProperties struct {
	XMLName    xml.Name            `xml:"http://www.w3.org/2000/09/xmldsig# SignatureProperties"`
	ID         string              `xml:"Id,attr,omitempty"`
	Properties []SignatureProperty `xml:"SignatureProperty"`
}

type Signature struct {
	XMLName        xml.Name        `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     *SignedInfo     `xml:"SignedInfo"`
	SignatureValue *SignatureValue `xml:"SignatureValue"`
	KeyInfo        *KeyInfo        `xml:"KeyInfo"`
	Objects        []Object        `xml:"Object"`
	el             *etree.Element
}

// SetUnderlyingElement will be called with a reference to the Element this Signature
// was unmarshaled from.
func (s *Signature) SetUnderlyingElement(el *etree.Element) {
	s.el = el
}

// UnderlyingElement returns a reference to the Element this signature was unmarshaled
// from, where applicable.
func (s *Signature) UnderlyingElement() *etree.Element {
	return s.el
}
