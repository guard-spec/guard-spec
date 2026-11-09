// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

// testIdP signs SAML responses like an identity provider would.
type testIdP struct {
	entityID string
	ssoURL   string
	key      *rsa.PrivateKey
	cert     []byte // DER
}

func newTestIdP(t testing.TB, entityID string) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdP{entityID: entityID, ssoURL: "https://idp.example.com/sso", key: key, cert: der}
}

func (i *testIdP) metadata() string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, i.entityID, base64.StdEncoding.EncodeToString(i.cert), i.ssoURL, i.ssoURL)
}

func (i *testIdP) keyStore() dsig.X509KeyStore {
	return dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{i.cert}, PrivateKey: i.key})
}

// assertionOpts describe one response; the zero value is a valid login.
type assertionOpts struct {
	acs, audience, issuer, inResponseTo string
	nameID, email, name                 string
	groups                              []string
	notBefore, notOnOrAfter             time.Time
	noAudience                          bool
	signResponse, unsigned              bool
	assertionID                         string
}

func (i *testIdP) defaults(sp samlSPInfo, o *assertionOpts) {
	now := time.Now().UTC()
	if o.acs == "" {
		o.acs = sp.ACSURL
	}
	if o.audience == "" {
		o.audience = sp.EntityID
	}
	if o.issuer == "" {
		o.issuer = i.entityID
	}
	if o.nameID == "" {
		o.nameID = "user-123"
	}
	if o.email == "" {
		o.email = "Alice@Example.com"
	}
	if o.notBefore.IsZero() {
		o.notBefore = now.Add(-time.Minute)
	}
	if o.notOnOrAfter.IsZero() {
		o.notOnOrAfter = now.Add(5 * time.Minute)
	}
	if o.assertionID == "" {
		o.assertionID = "_a" + uuid.NewString()
	}
}

func (i *testIdP) assertion(o assertionOpts) *etree.Element {
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	a.CreateAttr("ID", o.assertionID)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", ts(time.Now()))
	a.CreateElement("saml:Issuer").SetText(o.issuer)
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
	nid.SetText(o.nameID)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("Recipient", o.acs)
	scd.CreateAttr("NotOnOrAfter", ts(o.notOnOrAfter))
	if o.inResponseTo != "" {
		scd.CreateAttr("InResponseTo", o.inResponseTo)
	}
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", ts(o.notBefore))
	cond.CreateAttr("NotOnOrAfter", ts(o.notOnOrAfter))
	if !o.noAudience {
		cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(o.audience)
	}
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", ts(time.Now()))
	attrs := a.CreateElement("saml:AttributeStatement")
	add := func(name string, values ...string) {
		at := attrs.CreateElement("saml:Attribute")
		at.CreateAttr("Name", name)
		for _, v := range values {
			at.CreateElement("saml:AttributeValue").SetText(v)
		}
	}
	add("email", o.email)
	if o.name != "" {
		add("displayName", o.name)
	}
	if len(o.groups) > 0 {
		add("groups", o.groups...)
	}
	return a
}

func (i *testIdP) sign(t testing.TB, el *etree.Element) *etree.Element {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(i.keyStore())
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (i *testIdP) responseEl(o assertionOpts, assertions ...*etree.Element) *etree.Element {
	r := etree.NewElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	r.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	r.CreateAttr("ID", "_r"+uuid.NewString())
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	r.CreateAttr("Destination", o.acs)
	if o.inResponseTo != "" {
		r.CreateAttr("InResponseTo", o.inResponseTo)
	}
	r.CreateElement("saml:Issuer").SetText(o.issuer)
	r.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").
		CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	for _, a := range assertions {
		r.AddChild(a)
	}
	return r
}

func encode(t testing.TB, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// response builds an encoded response for sp.
func (i *testIdP) response(t testing.TB, sp samlSPInfo, o assertionOpts) string {
	t.Helper()
	i.defaults(sp, &o)
	a := i.assertion(o)
	if !o.unsigned && !o.signResponse {
		a = i.sign(t, a)
	}
	r := i.responseEl(o, a)
	if o.signResponse {
		r = i.sign(t, r)
	}
	return encode(t, r)
}

func testSAMLProvider(t testing.TB, idp *testIdP, mutate func(*providerRow)) (*identity, *samlProvider, samlSPInfo) {
	t.Helper()
	id := &identity{publicURL: "https://guard.example.com", samlSPs: map[uuid.UUID]*samlProvider{}}
	row := providerRow{ID: uuid.New(), Type: "saml", DisplayName: "Test IdP", SAMLMetadata: idp.metadata(), Enabled: true,
		UpdatedAt: time.Now()}
	if mutate != nil {
		mutate(&row)
	}
	if err := row.validate(); err != nil {
		t.Fatal(err)
	}
	md, err := parseIdPMetadata(row.SAMLMetadata)
	if err != nil {
		t.Fatal(err)
	}
	info := id.spInfo(row.ID)
	p, err := buildSAMLProvider(row, md, info, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, p, info
}

func wantRefused(t *testing.T, err error, code string) {
	t.Helper()
	var se *errSAML
	if !errors.As(err, &se) {
		t.Fatalf("want refusal %s, got %v", code, err)
	}
	if code != "" && se.code != code {
		t.Fatalf("want code %s, got %s (%s)", code, se.code, se.reason)
	}
}

func TestSAMLMetadataParse(t *testing.T) {
	idp := newTestIdP(t, "https://idp.example.com/entity")
	md, err := parseIdPMetadata(idp.metadata())
	if err != nil {
		t.Fatal(err)
	}
	if md.entityID != idp.entityID || md.ssoURL != idp.ssoURL || len(md.certs) != 1 {
		t.Fatalf("metadata %+v", md)
	}
	// An EntitiesDescriptor holding the IdP also works.
	wrapped := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">` +
		strings.TrimPrefix(idp.metadata(), `<?xml version="1.0"?>`) + `</md:EntitiesDescriptor>`
	if _, err := parseIdPMetadata(wrapped); err != nil {
		t.Fatalf("entities descriptor: %v", err)
	}
	for name, raw := range map[string]string{
		"not xml":     "hello",
		"no idp":      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>`,
		"no redirect": strings.Replace(idp.metadata(), "bindings:HTTP-Redirect", "bindings:SOAP", 1),
		"no cert":     strings.Replace(idp.metadata(), `use="signing"`, `use="encryption"`, 1),
		"http sso":    strings.ReplaceAll(idp.metadata(), "https://idp.example.com/sso", "http://idp.example.com/sso"),
		"bad cert":    strings.Replace(idp.metadata(), "<ds:X509Certificate>", "<ds:X509Certificate>AAAA", 1),
	} {
		if _, err := parseIdPMetadata(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSAMLProviderValidate(t *testing.T) {
	idp := newTestIdP(t, "https://idp.example.com/entity")
	p := providerRow{Type: "saml", DisplayName: "Okta", SAMLMetadata: idp.metadata(), ClientID: "x",
		ClientSecretEnv: "OIDC_SECRET_X", SAMLGroupsAttribute: " groups "}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.Issuer != idp.entityID || p.ClientID != "" || p.ClientSecretEnv != "" || p.SAMLGroupsAttribute != "groups" {
		t.Fatalf("validated %+v", p)
	}
	if p.method() != "saml:"+p.ID.String() {
		t.Fatal(p.method())
	}
	bad := providerRow{Type: "saml", DisplayName: "x"}
	if err := bad.validate(); err == nil {
		t.Fatal("no metadata accepted")
	}
	bad = providerRow{Type: "saml", DisplayName: "x", SAMLMetadata: idp.metadata(), SAMLEmailAttribute: `a"b`}
	if err := bad.validate(); err == nil {
		t.Fatal("bad attribute name accepted")
	}
	// An OIDC provider drops SAML fields.
	o := providerRow{Type: "oidc", DisplayName: "x", Issuer: "https://issuer.example.com", ClientID: "c",
		ClientSecretEnv: "OIDC_SECRET_C", SAMLMetadata: "junk", SAMLAllowIdPInitiated: true}
	if err := o.validate(); err != nil || o.SAMLMetadata != "" || o.SAMLAllowIdPInitiated {
		t.Fatalf("oidc: %v %+v", err, o)
	}
}

func TestSAMLVerifyResponse(t *testing.T) {
	idp := newTestIdP(t, "https://idp.example.com/entity")
	_, p, sp := testSAMLProvider(t, idp, nil)

	l, err := verifyResponse(p, idp.response(t, sp, assertionOpts{inResponseTo: "_req1", name: "Alice",
		groups: []string{"Admins", "Everyone"}}))
	if err != nil {
		t.Fatal(err)
	}
	if l.subject != "user-123" || l.email != "alice@example.com" || l.name != "Alice" || l.inResponseTo != "_req1" ||
		len(l.groups) != 2 || l.assertionID == "" || l.expires.IsZero() {
		t.Fatalf("login %+v", l)
	}
	// A signed Response around an unsigned assertion is accepted too.
	if _, err := verifyResponse(p, idp.response(t, sp, assertionOpts{signResponse: true})); err != nil {
		t.Fatalf("signed response: %v", err)
	}
	// The email falls back to an email-shaped NameID.
	if l, err := verifyResponse(p, idp.response(t, sp, assertionOpts{nameID: "bob@example.com", email: " "})); err != nil ||
		l.email != "bob@example.com" {
		t.Fatalf("nameid email: %v %+v", err, l)
	}
}

func TestSAMLVerifyRefusals(t *testing.T) {
	idp := newTestIdP(t, "https://idp.example.com/entity")
	other := newTestIdP(t, "https://idp.example.com/entity")
	_, p, sp := testSAMLProvider(t, idp, nil)
	past := time.Now().Add(-10 * time.Minute)

	cases := map[string]struct {
		resp string
		code string
	}{
		"unsigned":          {idp.response(t, sp, assertionOpts{unsigned: true}), "invalid_response"},
		"other key":         {other.response(t, sp, assertionOpts{}), "invalid_response"},
		"wrong audience":    {idp.response(t, sp, assertionOpts{audience: "https://other.example.com"}), "invalid_response"},
		"no audience":       {idp.response(t, sp, assertionOpts{noAudience: true}), "invalid_response"},
		"wrong recipient":   {idp.response(t, sp, assertionOpts{acs: "https://evil.example.com/acs"}), "invalid_response"},
		"wrong issuer":      {idp.response(t, sp, assertionOpts{issuer: "https://evil.example.com"}), "invalid_response"},
		"expired":           {idp.response(t, sp, assertionOpts{notBefore: past.Add(-time.Minute), notOnOrAfter: past}), ""},
		"not yet valid":     {idp.response(t, sp, assertionOpts{notBefore: time.Now().Add(10 * time.Minute)}), "expired"},
		"no email":          {idp.response(t, sp, assertionOpts{email: "not-an-email"}), "email_not_verified"},
		"long nameid":       {idp.response(t, sp, assertionOpts{nameID: strings.Repeat("x", 300)}), "invalid_response"},
		"garbage":           {base64.StdEncoding.EncodeToString([]byte("<x/>")), "invalid_response"},
		"not base64":        {"%%%", "invalid_response"},
		"too large":         {strings.Repeat("A", samlMaxBody+4), "invalid_response"},
		"tampered nameid":   {tamper(t, idp.response(t, sp, assertionOpts{}), "user-123", "admin-1"), "invalid_response"},
		"tampered audience": {tamper(t, idp.response(t, sp, assertionOpts{}), sp.EntityID, sp.EntityID+"x"), "invalid_response"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := verifyResponse(p, c.resp)
			wantRefused(t, err, c.code)
		})
	}
}

// tamper replaces text in an encoded response after it was signed.
func tamper(t *testing.T, encoded, from, to string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, from) {
		t.Fatalf("%q not in response", from)
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Replace(s, from, to, 1)))
}

// XML signature wrapping: a signed assertion for the attacker's own account
// is moved around and a forged one put where a naive parser would read it.
func TestSAMLSignatureWrapping(t *testing.T) {
	idp := newTestIdP(t, "https://idp.example.com/entity")
	_, p, sp := testSAMLProvider(t, idp, nil)

	signedFor := func(nameID string) *etree.Element {
		o := assertionOpts{nameID: nameID}
		idp.defaults(sp, &o)
		return idp.sign(t, idp.assertion(o))
	}
	forged := func() *etree.Element {
		o := assertionOpts{nameID: "victim", email: "victim@example.com"}
		idp.defaults(sp, &o)
		return idp.assertion(o)
	}
	base := assertionOpts{}
	idp.defaults(sp, &base)

	attacks := map[string]*etree.Element{
		// forged first, genuine signed second
		"forged before signed": idp.responseEl(base, forged(), signedFor("attacker")),
		// genuine signed first, forged second
		"forged after signed": idp.responseEl(base, signedFor("attacker"), forged()),
	}
	// The signed assertion hidden in an extension, the forged one in its place.
	r := idp.responseEl(base, forged())
	ext := etree.NewElement("samlp:Extensions")
	ext.AddChild(signedFor("attacker"))
	r.InsertChildAt(1, ext)
	attacks["signed inside extensions"] = r
	// The forged assertion carries the genuine signature (same ID).
	genuine := signedFor("attacker")
	f := forged()
	f.RemoveAttr("ID")
	f.CreateAttr("ID", genuine.SelectAttrValue("ID", ""))
	if sig := genuine.FindElement("./Signature"); sig != nil {
		f.InsertChildAt(1, sig.Copy())
	}
	attacks["copied signature"] = idp.responseEl(base, f)
	// The genuine assertion nested inside the forged one.
	f2 := forged()
	f2.AddChild(signedFor("attacker"))
	attacks["signed nested in forged"] = idp.responseEl(base, f2)
	// A signed response whose assertion was swapped for a forged one.
	sr := idp.sign(t, idp.responseEl(base, idp.assertion(base)))
	for _, a := range sr.ChildElements() {
		if a.Tag == "Assertion" {
			sr.RemoveChild(a)
		}
	}
	sr.AddChild(forged())
	attacks["swapped in signed response"] = sr

	for name, el := range attacks {
		t.Run(name, func(t *testing.T) {
			l, err := verifyResponse(p, encode(t, el))
			if err == nil {
				t.Fatalf("accepted as %q", l.subject)
			}
			if l.subject == "victim" {
				t.Fatal("forged subject read")
			}
			wantRefused(t, err, "")
		})
	}
}

func TestSAMLAttributes(t *testing.T) {
	idp := newTestIdP(t, "https://idp.example.com/entity")
	_, p, sp := testSAMLProvider(t, idp, func(r *providerRow) { r.SAMLGroupsAttribute = "teams" })
	// The configured groups attribute replaces the defaults: "groups" is ignored.
	l, err := verifyResponse(p, idp.response(t, sp, assertionOpts{groups: []string{"Admins"}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.groups) != 0 {
		t.Fatalf("groups %v", l.groups)
	}
}

func TestSAMLMethod(t *testing.T) {
	p := providerRow{ID: uuid.New(), Type: "saml"}
	if !strings.HasPrefix(p.method(), "saml:") {
		t.Fatal(p.method())
	}
}
