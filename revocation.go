package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ---- pool of certificates / revocation data embedded in the PDF ----

type pool struct {
	certs       []*x509.Certificate
	crls, ocsps [][]byte
	seen        map[[32]byte]bool
	budget      int64 // bytes left for decompressing PDF streams
}

func newPool() *pool { return &pool{seen: map[[32]byte]bool{}, budget: 200 << 20} }

func (p *pool) addCert(c *x509.Certificate) {
	if h := sha256.Sum256(c.Raw); !p.seen[h] {
		p.seen[h] = true
		p.certs = append(p.certs, c)
	}
}

func (p *pool) tryAdd(der []byte) bool {
	h := sha256.Sum256(der)
	if p.seen[h] {
		return true
	}
	if c, err := x509.ParseCertificate(der); err == nil {
		p.addCert(c)
		return true
	}
	if _, err := x509.ParseRevocationList(der); err == nil {
		p.seen[h] = true
		p.crls = append(p.crls, der)
		return true
	}
	if isOCSPResponse(der) {
		p.seen[h] = true
		p.ocsps = append(p.ocsps, der)
		return true
	}
	return false
}

// harvest walks a DER tree and collects certificates, CRLs and OCSP responses.
func (p *pool) harvest(der []byte, depth int) {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(der, &v); err != nil || !v.IsCompound || depth > 8 {
		return
	}
	if v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSequence && p.tryAdd(v.FullBytes) {
		return
	}
	for rest := v.Bytes; len(rest) > 0; {
		var ch asn1.RawValue
		r, err := asn1.Unmarshal(rest, &ch)
		if err != nil {
			return
		}
		p.harvest(ch.FullBytes, depth+1)
		rest = r
	}
}

var oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

func isOCSPResponse(der []byte) bool {
	var r struct {
		Status asn1.Enumerated
		Bytes  struct {
			Type     asn1.ObjectIdentifier
			Response []byte
		} `asn1:"explicit,tag:0,optional"`
	}
	_, err := asn1.Unmarshal(der, &r)
	return err == nil && r.Status == 0 && r.Bytes.Type.Equal(oidOCSPBasic)
}

// ---- evaluation at date S ----

type revStatus int

const (
	revUnknown revStatus = iota
	revGood
	revRevoked
)

type revEvidence struct {
	Kind, Source, File string
	Issuer, Number     string
	SHA256             string
	Status             revStatus
	ThisUpdate         time.Time
	NextUpdate         time.Time
	ProducedAt         time.Time
	ArchiveCutoff      time.Time
	RevokedAt          time.Time
	Invalidity         time.Time
	Reason             int
	Note               string
}

var reasons = map[int]string{0: "nieokreślony", 1: "kompromitacja klucza (keyCompromise)", 2: "kompromitacja CA",
	3: "zmiana przynależności", 4: "zastąpiony", 5: "zaprzestanie działalności", 6: "zawieszenie (certificateHold)",
	8: "removeFromCRL", 9: "wycofanie uprawnień", 10: "kompromitacja AA"}

func (e *revEvidence) revoked(S time.Time) {
	if !e.RevokedAt.After(S) {
		e.Status = revRevoked
		e.Note = "unieważniony " + fmtTime(e.RevokedAt) + " — przed datą podpisu; powód: " + reasons[e.Reason]
		return
	}
	// eIDAS art. 28 ust. 4: certyfikat traci ważność od chwili unieważnienia.
	e.Status = revGood
	e.Note = "unieważniony dopiero " + fmtTime(e.RevokedAt) + " — po dacie podpisu; powód: " + reasons[e.Reason]
}

// evalCRL returns nil if the CRL is not issued by issuer or its signature is invalid.
func evalCRL(cert, issuer *x509.Certificate, der []byte, S time.Time) *revEvidence {
	rl, err := x509.ParseRevocationList(der)
	if err != nil || !bytes.Equal(rl.RawIssuer, cert.RawIssuer) ||
		issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 ||
		checkSigned(issuer, rl.SignatureAlgorithm, rl.RawTBSRevocationList, rl.Signature) != nil {
		return nil
	}
	ev := &revEvidence{Kind: "CRL", ThisUpdate: rl.ThisUpdate, NextUpdate: rl.NextUpdate, Issuer: rl.Issuer.String(), SHA256: sha256hex(der)}
	if rl.Number != nil {
		ev.Number = rl.Number.String()
	}
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			continue
		}
		ev.RevokedAt, ev.Reason = e.RevocationTime, e.ReasonCode
		for _, x := range e.Extensions {
			if x.Id.String() == "2.5.29.24" { // invalidityDate
				asn1.Unmarshal(x.Value, &ev.Invalidity)
			}
		}
		ev.revoked(S)
		return ev
	}
	var delta bool
	var idpProblem string
	var expiredOn time.Time
	for _, x := range rl.Extensions {
		switch x.Id.String() {
		case "2.5.29.27":
			delta = true
		case "2.5.29.28":
			idpProblem = checkIDP(x.Value, cert)
		case "2.5.29.60": // ExpiredCertsOnCRL
			asn1.Unmarshal(x.Value, &expiredOn)
		}
	}
	switch {
	case delta:
		ev.Note = "delta CRL — brak wpisu nie jest dowodem"
	case idpProblem != "":
		ev.Note = idpProblem + " — brak wpisu nie jest dowodem"
	case rl.ThisUpdate.Before(S):
		ev.Note = "CRL wydana przed datą podpisu — nie dowodzi stanu na tę datę"
	case cert.NotAfter.Before(rl.ThisUpdate) && (expiredOn.IsZero() || expiredOn.After(cert.NotAfter)):
		ev.Note = "certyfikat wygasł przed wydaniem tej CRL — wpis mógł zostać z niej usunięty (RFC 5280 §3.3)"
	default:
		ev.Status = revGood
		ev.Note = "certyfikat nie figuruje na liście unieważnień wydanej po dacie podpisu"
	}
	return ev
}

// checkIDP returns why a CRL with this IssuingDistributionPoint (RFC 5280 §5.2.5) does not
// prove cert's status, or "" if it covers cert.
func checkIDP(der []byte, cert *x509.Certificate) string {
	var idp struct {
		DP          asn1.RawValue  `asn1:"optional,tag:0"` // [0] wrapping DistributionPointName (CHOICE → explicit)
		OnlyUser    bool           `asn1:"optional,tag:1"`
		OnlyCA      bool           `asn1:"optional,tag:2"`
		SomeReasons asn1.BitString `asn1:"optional,tag:3"`
		Indirect    bool           `asn1:"optional,tag:4"`
		OnlyAttr    bool           `asn1:"optional,tag:5"`
	}
	if rest, err := asn1.Unmarshal(der, &idp); err != nil || len(rest) > 0 {
		return "nieprawidłowe rozszerzenie IssuingDistributionPoint"
	}
	switch {
	case idp.OnlyCA && !cert.IsCA, idp.OnlyUser && cert.IsCA, idp.OnlyAttr:
		return "CRL obejmuje inny rodzaj certyfikatów (IDP onlyContains…)"
	case idp.SomeReasons.BitLength > 0:
		return "CRL obejmuje tylko wybrane powody unieważnienia (IDP onlySomeReasons)"
	case idp.Indirect:
		return "CRL pośrednia (IDP indirectCRL) — nieobsługiwana"
	case len(idp.DP.FullBytes) == 0:
		return ""
	}
	// fullName [0] GeneralNames; URIs are [6] IA5String. nameRelativeToCRLIssuer is not matched.
	var name asn1.RawValue
	if _, err := asn1.Unmarshal(idp.DP.Bytes, &name); err == nil && name.Class == asn1.ClassContextSpecific && name.Tag == 0 {
		for rest := name.Bytes; len(rest) > 0; {
			var gn asn1.RawValue
			r, err := asn1.Unmarshal(rest, &gn)
			if err != nil {
				break
			}
			rest = r
			if gn.Class == asn1.ClassContextSpecific && gn.Tag == 6 && slices.Contains(cert.CRLDistributionPoints, string(gn.Bytes)) {
				return ""
			}
		}
	}
	return "CRL częściowa (IDP) nieobejmująca punktu dystrybucji tego certyfikatu"
}

var oidArchiveCutoff = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6}

// evalOCSP returns nil if the response is not for cert or not signed by issuer (or its delegate).
// ponytail: delegated responder certificate's own revocation status is not checked.
func evalOCSP(cert, issuer *x509.Certificate, der []byte, S time.Time) *revEvidence {
	r, err := ocsp.ParseResponseForCert(der, cert, issuer)
	if err != nil {
		return nil
	}
	ev := &revEvidence{Kind: "OCSP", ThisUpdate: r.ThisUpdate, NextUpdate: r.NextUpdate, ProducedAt: r.ProducedAt, SHA256: sha256hex(der),
		Issuer: "responder = wystawca certyfikatu: " + issuer.Subject.String()}
	if r.Certificate != nil {
		ev.Issuer = "responder delegowany: " + r.Certificate.Subject.String()
	}
	switch r.Status {
	case ocsp.Revoked:
		ev.RevokedAt, ev.Reason = r.RevokedAt, r.RevocationReason
		ev.revoked(S)
	case ocsp.Good:
		for _, x := range r.Extensions {
			if x.Id.Equal(oidArchiveCutoff) {
				asn1.Unmarshal(x.Value, &ev.ArchiveCutoff)
			}
		}
		// RFC 6960 §4.4.4: status is retained for certificates that expired at or after ArchiveCutoff.
		archived := !ev.ArchiveCutoff.IsZero() && !ev.ArchiveCutoff.After(cert.NotAfter)
		expired := cert.NotAfter.Before(r.ThisUpdate)
		switch {
		case r.ThisUpdate.Before(S):
			ev.Note = "odpowiedź OCSP sprzed daty podpisu — nie dowodzi stanu na tę datę"
		case expired && !archived:
			ev.Note = "odpowiedź dla certyfikatu już wygasłego, bez ArchiveCutoff obejmującego jego ważność — niewiarygodna (RFC 6960 §4.4.4)"
		case expired:
			ev.Status = revGood
			ev.Note = "status „good” potwierdzony po dacie podpisu; certyfikat wygasł przed wydaniem odpowiedzi, ale responder przechowuje statusy certyfikatów wygasłych od " +
				fmtTime(ev.ArchiveCutoff) + " (ArchiveCutoff, RFC 6960 §4.4.4)"
		default:
			ev.Status = revGood
			ev.Note = "status „good” potwierdzony po dacie podpisu"
		}
	default:
		ev.Note = "status „unknown”"
	}
	return ev
}

func decide(evs []*revEvidence) (revStatus, *revEvidence) {
	var good *revEvidence
	for _, e := range evs {
		if e.Status == revRevoked {
			return revRevoked, e
		}
		if e.Status == revGood && good == nil {
			good = e
		}
	}
	if good != nil {
		return revGood, good
	}
	return revUnknown, nil
}

// checkRevocation: embedded evidence first, then online CRL, then OCSP — only while undecided.
func checkRevocation(cert, issuer *x509.Certificate, S time.Time, p *pool, n *netFetcher, ev *evidence) ([]*revEvidence, revStatus, *revEvidence) {
	var evs []*revEvidence
	add := func(e *revEvidence, src, file string) {
		if e != nil {
			e.Source, e.File = src, file
			evs = append(evs, e)
		}
	}
	for _, d := range p.crls {
		if e := evalCRL(cert, issuer, d, S); e != nil {
			add(e, "osadzona w PDF", ev.save("crl", "crl", d))
		}
	}
	for _, d := range p.ocsps {
		if e := evalOCSP(cert, issuer, d, S); e != nil {
			add(e, "osadzona w PDF", ev.save("ocsp", "der", d))
		}
	}
	if st, _ := decide(evs); st == revUnknown {
		for _, u := range cert.CRLDistributionPoints {
			if !strings.HasPrefix(u, "http") {
				continue
			}
			b, file, err := n.do(u, nil, "", 200<<20, "crl", "crl")
			if err != nil {
				evs = append(evs, &revEvidence{Kind: "CRL", Source: u, Note: "błąd pobierania: " + err.Error()})
				continue
			}
			if e := evalCRL(cert, issuer, b, S); e != nil {
				add(e, u, file)
			} else {
				evs = append(evs, &revEvidence{Kind: "CRL", Source: u, File: file, Note: "nie jest CRL wystawcy lub ma nieprawidłowy podpis"})
			}
		}
	}
	if st, _ := decide(evs); st == revUnknown && len(cert.OCSPServer) > 0 {
		if req, err := ocsp.CreateRequest(cert, issuer, nil); err == nil {
			for _, u := range cert.OCSPServer {
				b, file, err := n.do(u, req, "application/ocsp-request", 1<<20, "ocsp", "der")
				if err != nil {
					evs = append(evs, &revEvidence{Kind: "OCSP", Source: u, Note: "błąd zapytania: " + err.Error()})
					continue
				}
				if e := evalOCSP(cert, issuer, b, S); e != nil {
					add(e, u, file)
				} else {
					evs = append(evs, &revEvidence{Kind: "OCSP", Source: u, File: file, Note: "odpowiedź nieprawidłowa lub niepodpisana przez wystawcę"})
				}
			}
		}
	}
	st, dec := decide(evs)
	return evs, st, dec
}

func (s revStatus) String() string {
	return [...]string{"nierozstrzygające", "nieunieważniony na dzień podpisu", "UNIEWAŻNIONY"}[s]
}
