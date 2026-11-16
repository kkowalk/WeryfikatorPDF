package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Evidence details shown in the report (certificates, CMS, revocation, timeline).

type kv struct{ K, V string }

// Timeline event kinds; each is a CSS class (colour) in the report.
const (
	evSign     = "sign"     // date the signature is evaluated at
	evStart    = "start"    // certificate validity begins
	evStop     = "stop"     // certificate validity ends
	evRevoke   = "revoke"   // revocation / invalidityDate
	evEvidence = "evidence" // CRL/OCSP issued, report generated
)

type tlEvent struct {
	T                     time.Time
	When, What, Src, Kind string
	Rel                   string
}

func (s *sigReport) event(t time.Time, what, src, kind string) {
	if !t.IsZero() {
		s.Timeline = append(s.Timeline, tlEvent{T: t, What: what, Src: src, Kind: kind})
	}
}

// sortTimeline orders events and describes each one relative to the signing date.
func (s *sigReport) sortTimeline() {
	sort.SliceStable(s.Timeline, func(i, j int) bool { return s.Timeline[i].T.Before(s.Timeline[j].T) })
	for i := range s.Timeline {
		e := &s.Timeline[i]
		e.When = fmtTime(e.T)
		if !s.at.IsZero() {
			e.Rel = relTo(e.T, s.at)
		}
	}
}

func relTo(t, S time.Time) string {
	switch d := t.Sub(S); {
	case d == 0:
		return "data podpisu"
	case d < 0:
		return fmtDelta(-d) + " przed podpisem"
	default:
		return fmtDelta(d) + " po podpisie"
	}
}

func fmtDelta(d time.Duration) string {
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	parts := []string{}
	for _, p := range []struct {
		n    int
		unit string
	}{{days, "d"}, {int(d / time.Hour), "h"}, {int(d % time.Hour / time.Minute), "min"}, {int(d % time.Minute / time.Second), "s"}} {
		if p.n > 0 && len(parts) < 3 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.unit))
		}
	}
	if len(parts) == 0 {
		return "< 1 s"
	}
	return strings.Join(parts, " ")
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var keyUsageNames = []struct {
	b    x509.KeyUsage
	name string
}{{x509.KeyUsageDigitalSignature, "digitalSignature"}, {x509.KeyUsageContentCommitment, "nonRepudiation"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"}, {x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"}, {x509.KeyUsageCertSign, "keyCertSign"}, {x509.KeyUsageCRLSign, "cRLSign"}}

var qcNames = map[string]string{
	"0.4.0.1862.1.1": "QcCompliance (certyfikat kwalifikowany)", "0.4.0.1862.1.4": "QcSSCD (klucz w QSCD)",
	"0.4.0.1862.1.5": "QcPDS", "0.4.0.1862.1.6": "QcType", "0.4.0.1862.1.3": "QcRetentionPeriod",
	"0.4.0.1862.1.2": "QcLimitValue", "0.4.0.194121.1.1": "Semantics natural person", "0.4.0.194121.1.2": "Semantics legal person",
	"1.3.6.1.5.5.7.11.2": "Semantics (RFC 3739)",
}

func certDetails(c *x509.Certificate) []kv {
	out := []kv{
		{"Podmiot", c.Subject.String()},
		{"Wystawca", c.Issuer.String()},
		{"Numer seryjny (hex)", c.SerialNumber.Text(16)},
		{"Ważny od", fmtTime(c.NotBefore)},
		{"Ważny do", fmtTime(c.NotAfter)},
		{"Odcisk SHA-256", sha256hex(c.Raw)},
		{"Klucz publiczny", keyDesc(c.PublicKey)},
		{"Algorytm podpisu certyfikatu", c.SignatureAlgorithm.String()},
	}
	var ku []string
	for _, k := range keyUsageNames {
		if c.KeyUsage&k.b != 0 {
			ku = append(ku, k.name)
		}
	}
	add := func(k string, v []string) {
		if len(v) > 0 {
			out = append(out, kv{k, strings.Join(v, ", ")})
		}
	}
	add("Użycie klucza (keyUsage)", ku)
	var pol []string
	for _, p := range c.PolicyIdentifiers {
		pol = append(pol, p.String())
	}
	add("Polityki certyfikacji (OID)", pol)
	add("Deklaracje QcStatements", qcStatements(c))
	add("Punkty dystrybucji CRL", c.CRLDistributionPoints)
	add("Usługi OCSP", c.OCSPServer)
	add("Certyfikat wystawcy (AIA)", c.IssuingCertificateURL)
	if c.IsCA {
		out = append(out, kv{"Urząd certyfikacji (CA)", "tak"})
	}
	return out
}

func keyDesc(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bitów", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	}
	return fmt.Sprintf("%T", pub)
}

func qcStatements(c *x509.Certificate) []string {
	var out []string
	for _, x := range c.Extensions {
		if x.Id.String() != "1.3.6.1.5.5.7.1.3" {
			continue
		}
		var sts []struct {
			ID   asn1.ObjectIdentifier
			Info asn1.RawValue `asn1:"optional"`
		}
		asn1.Unmarshal(x.Value, &sts)
		for _, st := range sts {
			name := qcNames[st.ID.String()]
			if name == "" {
				name = st.ID.String()
			}
			if st.ID.String() == "0.4.0.1862.1.6" {
				var types []asn1.ObjectIdentifier
				asn1.Unmarshal(st.Info.FullBytes, &types)
				for _, t := range types {
					name += " " + map[string]string{"0.4.0.1862.1.6.1": "esign (podpis)", "0.4.0.1862.1.6.2": "eseal (pieczęć)", "0.4.0.1862.1.6.3": "web"}[t.String()]
				}
			}
			out = append(out, name)
		}
	}
	return out
}

var attrNames = map[string]string{
	"1.2.840.113549.1.9.3": "contentType", oidMessageDigest: "messageDigest", oidSigningTime: "signingTime",
	oidSigningCertV1: "signing-certificate", oidSigningCertV2: "signing-certificate-v2",
	oidSigTimestamp: "signature-time-stamp", oidAdbeRevInfo: "adbe-revocationInfoArchival",
	"1.2.840.113549.1.9.16.2.15": "signature-policy-identifier", "1.2.840.113549.1.9.52": "CMSAlgorithmProtection",
	"1.2.840.113549.1.9.16.2.21": "complete-certificate-references", "1.2.840.113549.1.9.16.2.22": "complete-revocation-references",
}

var sigAlgNames = map[string]string{
	"1.2.840.113549.1.1.1": "rsaEncryption (PKCS#1 v1.5)", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
	"1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
	"1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "RSASSA-PSS",
	"1.2.840.10045.2.1": "ecPublicKey (ECDSA)", "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
	"1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}

func attrList(m map[string]asn1.RawValue) string {
	var names []string
	for oid := range m {
		if n, ok := attrNames[oid]; ok {
			names = append(names, n)
		} else {
			names = append(names, oid)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "brak"
	}
	return strings.Join(names, ", ")
}

func cmsDetails(ps pdfSig, c *cmsSig) []kv {
	var raw asn1.RawValue
	asn1.Unmarshal(ps.DER, &raw) // strip /Contents zero padding
	br := ps.ByteRange
	out := []kv{
		{"SubFilter", ps.SubFilter},
		{"ByteRange", fmt.Sprintf("[%d %d %d %d] — podpisane bajty 0–%d oraz %d–%d", br[0], br[1], br[2], br[3], br[1]-1, br[2], br[2]+br[3]-1)},
		{"Struktura CMS", fmt.Sprintf("%d B, SHA-256 %s", len(raw.FullBytes), sha256hex(raw.FullBytes))},
	}
	sid := "issuerAndSerialNumber"
	if c.si.SID.Class == asn1.ClassContextSpecific {
		sid = "subjectKeyIdentifier"
	}
	out = append(out, kv{"Identyfikator podpisującego", sid})
	dalg := c.si.DigestAlgorithm.Algorithm.String()
	if h, ok := hashByOID[dalg]; ok {
		out = append(out, kv{"Algorytm skrótu", h.String() + " (" + dalg + ")"},
			kv{"Skrót zakresu ByteRange (obliczony)", hex.EncodeToString(digest(h, ps.Signed...))})
	} else {
		out = append(out, kv{"Algorytm skrótu", dalg})
	}
	var md []byte
	if _, err := asn1.Unmarshal(firstValue(c.signed[oidMessageDigest]), &md); err == nil {
		out = append(out, kv{"messageDigest (w podpisie)", hex.EncodeToString(md)})
	}
	salg := c.si.SignatureAlgorithm.Algorithm.String()
	if n, ok := sigAlgNames[salg]; ok {
		salg = n + " (" + salg + ")"
	}
	out = append(out,
		kv{"Algorytm podpisu", salg},
		kv{"Wartość podpisu", fmt.Sprintf("%d B, SHA-256 %s", len(c.si.Signature), sha256hex(c.si.Signature))},
		kv{"Atrybuty podpisane", attrList(c.signed)},
		kv{"Atrybuty niepodpisane", attrList(c.unsigned)},
		kv{"Certyfikaty dołączone do CMS", fmt.Sprint(len(c.certs))})
	return out
}

func revDetails(r *revEvidence, cert *x509.Certificate) []string {
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+": "+v)
		}
	}
	add("Nr seryjny certyfikatu", cert.SerialNumber.Text(16))
	add("Wystawca dowodu", r.Issuer)
	add("Numer CRL", r.Number)
	add("Wydano (thisUpdate)", fmtTime(r.ThisUpdate))
	add("Wygenerowano (producedAt)", fmtTime(r.ProducedAt))
	add("Następna aktualizacja", fmtTime(r.NextUpdate))
	add("ArchiveCutoff", fmtTime(r.ArchiveCutoff))
	add("Data unieważnienia", fmtTime(r.RevokedAt))
	if !r.RevokedAt.IsZero() {
		add("Powód", reasons[r.Reason])
	}
	add("invalidityDate", fmtTime(r.Invalidity))
	add("SHA-256 dowodu", r.SHA256)
	return out
}
