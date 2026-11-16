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

func TestFmtDelta(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "< 1 s", 90 * time.Second: "1 min 30 s",
		186*24*time.Hour + 21*time.Hour + 5*time.Minute + 9*time.Second: "186 d 21 h 5 min",
	} {
		if got := fmtDelta(d); got != want {
			t.Errorf("fmtDelta(%v) = %q, want %q", d, got, want)
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
	if err := c.verify(sigs[0].Signed...); err != nil {
		t.Fatal("valid signature rejected:", err)
	}
	if present, err := c.checkESS(); !present || err != nil {
		t.Fatal("ESS:", present, err)
	}
	// tamper with a signed byte outside /Contents
	bad := append([]byte{}, pdf...)
	bad[3] ^= 1
	if err := c.verify(findSignatures(bad)[0].Signed...); err == nil {
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

func issue(t *testing.T, tpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if parent == nil {
		parent, parentKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func tlWith(ca *x509.Certificate, typ, status string, start time.Time) *trust {
	return &trust{loaded: map[string]bool{"PL": true}, entries: []*tlEntry{{Country: "PL", TSP: "TSP", Service: "Usługa", Cert: ca,
		Timeline: []tlStatus{{start, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/" + status, "http://uri.etsi.org/TrstSvc/Svctype/" + typ}}}}}
}

func TestChainRequiresCAIssuers(t *testing.T) {
	ca, leaf, caKey, _ := pki(t, S.AddDate(1, 0, 0))
	tr := tlWith(ca, "CA/QC", "granted", S.AddDate(-1, 0, 0))
	if _, anchor, err := tr.chain(leaf, nil); err != nil || anchor == nil {
		t.Fatalf("valid chain rejected: %v %v", anchor, err)
	}
	// an end-entity certificate (no basicConstraints cA) must not act as an issuer
	ee, eeKey := issue(t, &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Atakujący"},
		NotBefore: S.AddDate(-1, 0, 0), NotAfter: S.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}, ca, caKey)
	forged, _ := issue(t, &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "Jan Kowalski"},
		NotBefore: S.AddDate(-1, 0, 0), NotAfter: S.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageContentCommitment}, ee, eeKey)
	if _, anchor, err := tr.chain(forged, []*x509.Certificate{ee}); err == nil || anchor != nil {
		t.Fatalf("chain through non-CA accepted: %v %v", anchor, err)
	}
	// pathLenConstraint=0 forbids an intermediate CA below
	ca0, ca0Key := issue(t, &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "CA0"},
		NotBefore: S.AddDate(-1, 0, 0), NotAfter: S.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	sub, subKey := issue(t, &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Sub"},
		NotBefore: S.AddDate(-1, 0, 0), NotAfter: S.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, ca0, ca0Key)
	l2, _ := issue(t, &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "L2"},
		NotBefore: S.AddDate(-1, 0, 0), NotAfter: S.AddDate(1, 0, 0)}, sub, subKey)
	if _, _, err := tlWith(ca0, "CA/QC", "granted", S.AddDate(-1, 0, 0)).chain(l2, []*x509.Certificate{sub}); err == nil {
		t.Fatal("pathLenConstraint ignored")
	}
}

func TestAnchorState(t *testing.T) {
	ca, _, _, _ := pki(t, S.AddDate(1, 0, 0))
	for _, c := range []struct {
		typ, status string
		start       time.Time
		want        string
	}{
		{"CA/QC", "granted", S.AddDate(-1, 0, 0), "ok"},
		{"CA/QC", "withdrawn", S.AddDate(0, -1, 0), "fail"},
		{"CA/QC", "granted", S.AddDate(0, 1, 0), "unknown"}, // listed only after S
		{"TSA/QTST", "granted", S.AddDate(-1, 0, 0), "unknown"},
	} {
		if got, _ := anchorState(tlWith(ca, c.typ, c.status, c.start).entries, S); got != c.want {
			t.Errorf("%s %s %v: got %s, want %s", c.typ, c.status, c.start, got, c.want)
		}
	}
}

func TestEvalTSTiers(t *testing.T) {
	ca, _, caKey, _ := pki(t, S.AddDate(1, 0, 0))
	tsaTpl := func(eku []x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "TSA"},
			NotBefore: S.AddDate(-1, 0, 0), NotAfter: S.AddDate(1, 0, 0), ExtKeyUsage: eku}
	}
	tsEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	tsa, _ := issue(t, tsaTpl(tsEKU), ca, caKey)
	noEKU, _ := issue(t, tsaTpl(nil), ca, caKey)
	self, _ := issue(t, tsaTpl(tsEKU), nil, nil)
	for _, c := range []struct {
		name string
		tsa  *x509.Certificate
		tr   *trust
		want int
	}{
		{"kwalifikowany", tsa, tlWith(ca, "TSA/QTST", "granted", S.AddDate(-1, 0, 0)), 0},
		{"zaufany niekwalifikowany", tsa, tlWith(ca, "CA/QC", "granted", S.AddDate(-1, 0, 0)), 1},
		{"bez EKU", noEKU, tlWith(ca, "TSA/QTST", "granted", S.AddDate(-1, 0, 0)), 2},
		{"self-signed", self, tlWith(ca, "TSA/QTST", "granted", S.AddDate(-1, 0, 0)), 2},
		{"usługa wycofana", tsa, tlWith(ca, "TSA/QTST", "withdrawn", S.AddDate(0, -1, 0)), 2},
	} {
		e := &env{trust: c.tr}
		if _, tier, err := e.evalTS(&tsResult{GenTime: S, TSA: c.tsa}, newPool()); err != nil || tier != c.want {
			t.Errorf("%s: tier %d err %v, want %d", c.name, tier, err, c.want)
		}
	}
}

func TestCheckIDP(t *testing.T) {
	idp := func(uri string, onlyCA bool) []byte {
		gn, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(uri)})
		full, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: gn})
		b, _ := asn1.Marshal(struct {
			DP     asn1.RawValue
			OnlyCA bool `asn1:"optional,tag:2"`
		}{asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: full}, onlyCA})
		return b
	}
	cert := &x509.Certificate{CRLDistributionPoints: []string{"http://ca.example/crl1.crl"}}
	if p := checkIDP(idp("http://ca.example/crl1.crl", false), cert); p != "" {
		t.Error("matching IDP rejected:", p)
	}
	if checkIDP(idp("http://ca.example/crl1.crl0", false), cert) == "" {
		t.Error("IDP matched by substring")
	}
	if checkIDP(idp("http://ca.example/crl1.crl", true), cert) == "" {
		t.Error("onlyContainsCACerts CRL accepted for an end-entity certificate")
	}
}
