package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

var S = time.Date(2024, 3, 5, 13, 22, 10, 0, time.UTC)

func pki(t *testing.T, leafNotAfter time.Time) (ca, leaf *x509.Certificate, caKey, leafKey *ecdsa.PrivateKey) {
	caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA", Country: []string{"PL"}},
		NotBefore: S.AddDate(-5, 0, 0), NotAfter: S.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(der)
	lT := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "Jan Testowy"},
		NotBefore: S.AddDate(-1, 0, 0), NotAfter: leafNotAfter, KeyUsage: x509.KeyUsageContentCommitment}
	der, err = x509.CreateCertificate(rand.Reader, lT, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	return
}

func TestEvalCRLAtSigningDate(t *testing.T) {
	cases := []struct {
		name       string
		notAfter   time.Time
		thisUpdate time.Time
		revokedAt  time.Time // zero = not listed
		want       revStatus
	}{
		{"unieważniony przed S", S.AddDate(1, 0, 0), S.AddDate(0, 1, 0), S.Add(-24 * time.Hour), revRevoked},
		{"unieważniony po S", S.AddDate(1, 0, 0), S.AddDate(0, 1, 0), S.Add(24 * time.Hour), revGood},
		{"brak na CRL wydanej po S", S.AddDate(1, 0, 0), S.Add(time.Hour), time.Time{}, revGood},
		{"CRL sprzed S", S.AddDate(1, 0, 0), S.Add(-time.Hour), time.Time{}, revUnknown},
		{"cert wygasł przed CRL", S.AddDate(0, 0, 10), S.AddDate(0, 0, 30), time.Time{}, revUnknown},
	}
	for _, c := range cases {
		ca, leaf, caKey, _ := pki(t, c.notAfter)
		tpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: c.thisUpdate, NextUpdate: c.thisUpdate.AddDate(0, 0, 7)}
		if !c.revokedAt.IsZero() {
			tpl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: c.revokedAt, ReasonCode: 1}}
		}
		der, err := x509.CreateRevocationList(rand.Reader, tpl, ca, caKey)
		if err != nil {
			t.Fatal(err)
		}
		ev := evalCRL(leaf, ca, der, S)
		if ev == nil || ev.Status != c.want {
			t.Errorf("%s: got %+v, want %v", c.name, ev, c.want)
		}
		// a CRL signed by someone else must be ignored
		other, _, _, _ := pki(t, c.notAfter)
		if evalCRL(leaf, other, der, S) != nil {
			t.Errorf("%s: CRL accepted with wrong issuer", c.name)
		}
	}
}

func TestPAdESEndToEnd(t *testing.T) {
	_, leaf, _, key := pki(t, S.AddDate(1, 0, 0))
	pdf := buildPDF(t, leaf, key)
	sigs := findSignatures(pdf)
	if len(sigs) != 1 || sigs[0].SubFilter != "ETSI.CAdES.detached" || !sigs[0].M.Equal(S) || sigs[0].End != int64(len(pdf)) {
		t.Fatalf("findSignatures: %+v", sigs)
	}
	c, err := parseCMS(sigs[0].DER)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.verify(sigs[0].Signed); err != nil {
		t.Fatal("valid signature rejected:", err)
	}
	if present, err := c.checkESS(); !present || err != nil {
		t.Fatal("ESS:", present, err)
	}
	// tamper with a signed byte outside /Contents
	bad := append([]byte{}, pdf...)
	bad[3] ^= 1
	if err := c.verify(findSignatures(bad)[0].Signed); err == nil {
		t.Fatal("tampered document accepted")
	}
}

func buildPDF(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	const n = 8192
	head := "%%PDF-1.7\n1 0 obj\n<< /Type /Sig /SubFilter /ETSI.CAdES.detached /M (D:20240305142210+01'00') /ByteRange [0 %010d %010d %010d] /Contents "
	tail := " >>\nendobj\ntrailer\n%%EOF\n"
	b := len(fmt.Sprintf(head, 0, 0, 0))
	c := b + n + 2
	h := fmt.Sprintf(head, b, c, len(tail))
	signed := []byte(h + tail)
	der := buildCMS(t, signed, cert, key)
	hx := hex.EncodeToString(der)
	return []byte(h + "<" + hx + strings.Repeat("0", n-len(hx)) + ">" + tail)
}

func buildCMS(t *testing.T, content []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	oid := func(s string) asn1.ObjectIdentifier {
		var o asn1.ObjectIdentifier
		for _, p := range strings.Split(s, ".") {
			var v int
			fmt.Sscan(p, &v)
			o = append(o, v)
		}
		return o
	}
	must := func(b []byte, err error) []byte {
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	attr := func(o string, v any) []byte {
		val := must(asn1.Marshal(v))
		return must(asn1.Marshal(attribute{oid(o), asn1.RawValue{Tag: 17, IsCompound: true, Bytes: val}}))
	}
	md := sha256.Sum256(content)
	ch := sha256.Sum256(cert.Raw)
	type essv2 struct{ Hash []byte }
	attrs := append(append(attr("1.2.840.113549.1.9.3", oid("1.2.840.113549.1.7.1")), attr(oidMessageDigest, md[:])...),
		attr(oidSigningCertV2, struct{ Certs []essv2 }{[]essv2{{ch[:]}}})...)
	set := must(asn1.Marshal(asn1.RawValue{Tag: 17, IsCompound: true, Bytes: attrs}))
	d := sha256.Sum256(set)
	sig := must(ecdsa.SignASN1(rand.Reader, key, d[:]))
	ias := must(asn1.Marshal(struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: cert.RawIssuer}, cert.SerialNumber}))
	sha := pkix.AlgorithmIdentifier{Algorithm: oid("2.16.840.1.101.3.4.2.1")}
	sd := signedData{Version: 1, DigestAlgorithms: []pkix.AlgorithmIdentifier{sha},
		EncapContent: encapContentInfo{EContentType: oid("1.2.840.113549.1.7.1")},
		Certificates: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: cert.Raw},
		SignerInfos: []signerInfo{{Version: 1, SID: asn1.RawValue{FullBytes: ias}, DigestAlgorithm: sha,
			SignedAttrs:        asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: attrs},
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid("1.2.840.10045.4.3.2")}, Signature: sig}}}
	return must(asn1.Marshal(contentInfo{oidSignedData, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: must(asn1.Marshal(sd))}}))
}
