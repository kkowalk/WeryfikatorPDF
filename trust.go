package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const lotlURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

// ---- evidence files ----

type evidence struct {
	dir   string
	saved map[[32]byte]string
	Errs  []string // failed writes, listed in index.html
}

// save stores b under dowody/ and returns the path relative to the report folder.
func (e *evidence) save(prefix, ext string, b []byte) string {
	h := sha256.Sum256(b)
	if p, ok := e.saved[h]; ok {
		return p
	}
	name := fmt.Sprintf("%s-%x.%s", prefix, h[:8], ext)
	err := os.MkdirAll(filepath.Join(e.dir, "dowody"), 0o700)
	if err == nil {
		err = os.WriteFile(filepath.Join(e.dir, "dowody", name), b, 0o600)
	}
	if err != nil {
		e.Errs = append(e.Errs, "Nie zapisano dowodu "+name+": "+err.Error())
		return ""
	}
	e.saved[h] = "dowody/" + name
	return e.saved[h]
}

// ---- network ----

type fetchLog struct{ When, Method, URL, Result, File string }

type fetched struct {
	body []byte
	file string
	err  error
}

type netFetcher struct {
	client  *http.Client
	ev      *evidence
	cache   map[string]fetched
	Log     []fetchLog
	offline bool
}

// checkRedirect blocks HTTPS→HTTP downgrades and redirects to local/private addresses.
// ponytail: only IP literals and "localhost" are checked; host names resolving to private
// addresses pass (a Dialer.Control check would also block corporate proxies).
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("zbyt wiele przekierowań")
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("przekierowanie z HTTPS na HTTP zablokowane")
	}
	h := req.URL.Hostname()
	if ip := net.ParseIP(h); strings.EqualFold(h, "localhost") || ip != nil &&
		(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		return errors.New("przekierowanie na adres lokalny zablokowane")
	}
	return nil
}

// do performs a GET (body==nil) or POST. Only data derived from certificates
// (CRL/OCSP/TL URLs, serial numbers) is ever sent — never the document.
func (n *netFetcher) do(url string, body []byte, ctype string, limit int64, prefix, ext string) ([]byte, string, error) {
	key := url + "\x00" + string(body)
	if f, ok := n.cache[key]; ok {
		return f.body, f.file, f.err
	}
	f := n.fetch(url, body, ctype, limit)
	if f.err == nil {
		f.file = n.ev.save(prefix, ext, f.body)
	}
	method := "GET"
	if body != nil {
		method = "POST"
	}
	res := "OK"
	if f.err != nil {
		res = f.err.Error()
	}
	n.Log = append(n.Log, fetchLog{time.Now().Format(time.RFC3339), method, url, res, f.file})
	n.cache[key] = f
	return f.body, f.file, f.err
}

func (n *netFetcher) fetch(url string, body []byte, ctype string, limit int64) fetched {
	if n.offline {
		return fetched{err: fmt.Errorf("tryb offline")}
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fetched{err: fmt.Errorf("nieobsługiwany schemat URL")}
	}
	var req *http.Request
	var err error
	if body == nil {
		req, err = http.NewRequest(http.MethodGet, url, nil)
	} else {
		req, err = http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", ctype)
	}
	if err != nil {
		return fetched{err: err}
	}
	req.Header.Set("User-Agent", "weryfikator-podpisow/"+version)
	resp, err := n.client.Do(req)
	if err != nil {
		return fetched{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fetched{err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fetched{err: err}
	}
	if int64(len(b)) > limit {
		return fetched{err: fmt.Errorf("odpowiedź przekracza limit %d B", limit)}
	}
	return fetched{body: b}
}

// ---- EU trusted lists (ETSI TS 119 612) ----

type tslXML struct {
	Pointers []struct {
		Location string `xml:"TSLLocation"`
		Info     []struct {
			Territory string `xml:"SchemeTerritory"`
			Mime      string `xml:"MimeType"`
		} `xml:"AdditionalInformation>OtherInformation"`
	} `xml:"SchemeInformation>PointersToOtherTSL>OtherTSLPointer"`
	Providers []struct {
		Names    []string `xml:"TSPInformation>TSPName>Name"`
		Services []struct {
			Type    string   `xml:"ServiceInformation>ServiceTypeIdentifier"`
			Names   []string `xml:"ServiceInformation>ServiceName>Name"`
			Certs   []string `xml:"ServiceInformation>ServiceDigitalIdentity>DigitalId>X509Certificate"`
			Status  string   `xml:"ServiceInformation>ServiceStatus"`
			Start   string   `xml:"ServiceInformation>StatusStartingTime"`
			ASI     []string `xml:"ServiceInformation>ServiceInformationExtensions>Extension>AdditionalServiceInformation>URI"`
			History []struct {
				Type   string `xml:"ServiceTypeIdentifier"`
				Status string `xml:"ServiceStatus"`
				Start  string `xml:"StatusStartingTime"`
			} `xml:"ServiceHistory>ServiceHistoryInstance"`
		} `xml:"TSPServices>TSPService"`
	} `xml:"TrustServiceProviderList>TrustServiceProvider"`
}

type tlStatus struct {
	Start        time.Time
	Status, Type string
}

type tlEntry struct {
	Country, TSP, Service string
	Cert                  *x509.Certificate
	Timeline              []tlStatus // ascending by Start
	File, URL             string
	ASI                   []string // AdditionalServiceInformation URIs (ForeSignatures, ForeSeals, ...)
}

// at returns the service status/type in force at t (ServiceHistory included).
func (e *tlEntry) at(t time.Time) (tlStatus, bool) {
	var cur tlStatus
	ok := false
	for _, s := range e.Timeline {
		if !s.Start.After(t) {
			cur, ok = s, true
		}
	}
	return cur, ok
}

// allows reports whether the service may issue certificates for signatures (or seals).
// ponytail: ASI of the current entry only; ServiceHistory qualifiers are not read.
func (e *tlEntry) allows(seal bool) bool {
	want := map[bool]string{false: "/ForeSignatures", true: "/ForeSeals"}[seal]
	for _, u := range e.ASI {
		if strings.HasSuffix(strings.TrimSpace(u), want) {
			return true
		}
	}
	return len(e.ASI) == 0
}

// anchorState: ok only if some matching service was a CA (CA/QC or CA/PKC) with a positive
// status at t; fail only if such a CA service had a negative status at t (a negative status of
// another service type, e.g. TSA, says nothing about issuing certificates); otherwise unknown.
func anchorState(anchor []*tlEntry, t time.Time) (state, detail string) {
	state, detail = "unknown", "Wystawca nie figurował na liście zaufanych usług w dniu podpisu (brak wpisu usługi na tę datę)."
	for _, a := range anchor {
		st, ok := a.at(t)
		ca := strings.HasSuffix(st.Type, "/CA/QC") || strings.HasSuffix(st.Type, "/CA/PKC")
		switch {
		case !ok:
		case ca && positive(st.Status):
			return "ok", fmt.Sprintf("%s — %s (%s), status %s od %s", a.TSP, a.Service, a.Country, path.Base(st.Status), fmtTime(st.Start))
		case ca:
			state, detail = "fail", fmt.Sprintf("Usługa wystawcy „%s” (%s, %s) miała na dzień podpisu status %s (od %s) — wystawca nie był wtedy zaufany.",
				a.Service, a.TSP, a.Country, path.Base(st.Status), fmtTime(st.Start))
		case state == "unknown":
			detail = fmt.Sprintf("Usługa „%s” (%s) jest typu %s — nie jest usługą wydawania certyfikatów (CA/QC, CA/PKC).",
				a.Service, a.TSP, strings.TrimPrefix(st.Type, "http://uri.etsi.org/TrstSvc/Svctype/"))
		}
	}
	return state, detail
}

func positive(status string) bool {
	switch path.Base(status) {
	case "granted", "accredited", "undersupervision", "supervisionincessation":
		return true
	}
	return false
}

// ponytail: TL XML signatures (XMLDSig) are not verified; integrity relies on HTTPS
// from the URLs published in the LOTL. Upgrade path: XMLDSig + C14N validation against
// the LOTL signing certificates published in the OJEU.
type trust struct {
	net      *netFetcher
	pointers map[string]string
	loaded   map[string]bool
	entries  []*tlEntry
	Errors   []string
}

func (t *trust) load(cc string) {
	cc = strings.ToUpper(cc)
	if cc == "GR" {
		cc = "EL"
	}
	if cc == "" || t.loaded[cc] {
		return
	}
	t.loaded[cc] = true
	if t.pointers == nil {
		t.pointers = map[string]string{}
		b, _, err := t.net.do(lotlURL, nil, "", 50<<20, "lotl", "xml")
		if err != nil {
			t.Errors = append(t.Errors, "Nie pobrano unijnej listy LOTL: "+err.Error())
			return
		}
		var l tslXML
		if err := xml.Unmarshal(b, &l); err != nil {
			t.Errors = append(t.Errors, "Nieprawidłowy plik LOTL: "+err.Error())
			return
		}
		for _, p := range l.Pointers {
			var terr, mime string
			for _, i := range p.Info {
				terr += i.Territory
				mime += i.Mime
			}
			if strings.Contains(mime, "xml") && strings.HasPrefix(p.Location, "https://") {
				t.pointers[terr] = strings.TrimSpace(p.Location)
			}
		}
	}
	u, ok := t.pointers[cc]
	if !ok {
		t.Errors = append(t.Errors, "Brak (HTTPS) listy zaufanych usług dla kraju "+cc+" w LOTL")
		return
	}
	b, file, err := t.net.do(u, nil, "", 50<<20, "tl-"+cc, "xml")
	if err != nil {
		t.Errors = append(t.Errors, "Nie pobrano listy zaufanych usług "+cc+": "+err.Error())
		return
	}
	var l tslXML
	if err := xml.Unmarshal(b, &l); err != nil {
		t.Errors = append(t.Errors, "Nieprawidłowa lista zaufanych usług "+cc+": "+err.Error())
		return
	}
	for _, p := range l.Providers {
		for _, s := range p.Services {
			tl := []tlStatus{{parseXSDTime(s.Start), s.Status, s.Type}}
			for _, h := range s.History {
				tl = append(tl, tlStatus{parseXSDTime(h.Start), h.Status, h.Type})
			}
			sort.Slice(tl, func(i, j int) bool { return tl[i].Start.Before(tl[j].Start) })
			for _, b64 := range s.Certs {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				t.entries = append(t.entries, &tlEntry{cc, first(p.Names), first(s.Names), cert, tl, file, u, s.ASI})
			}
		}
	}
}

func parseXSDTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(s))
	return t
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.TrimSpace(s[0])
}

// match returns TL services whose identity is cert (same subject and public key,
// so re-issued CA certificates with the same key also match).
func (t *trust) match(c *x509.Certificate) []*tlEntry {
	var out []*tlEntry
	for _, e := range t.entries {
		if bytes.Equal(e.Cert.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo) && bytes.Equal(e.Cert.RawSubject, c.RawSubject) {
			out = append(out, e)
		}
	}
	return out
}

// chain walks issuers from leaf until a certificate listed on an EU TL is reached.
// err reports a structurally invalid path (non-CA issuer, CA leaf, pathLen exceeded).
// ponytail: no AIA fetching — URLs from untrusted certificates are never contacted.
func (t *trust) chain(leaf *x509.Certificate, pool []*x509.Certificate) ([]*x509.Certificate, []*tlEntry, error) {
	all := append([]*x509.Certificate{}, pool...)
	for _, e := range t.entries {
		all = append(all, e.Cert)
	}
	chain := []*x509.Certificate{leaf}
	for cur := leaf; len(chain) <= 8; {
		if m := t.match(cur); len(m) > 0 {
			return chain, m, pathErr(chain)
		}
		next, nonCA := findIssuer(cur, all)
		if nonCA != nil {
			return append(chain, nonCA), nil, fmt.Errorf("certyfikat %s został wystawiony przez certyfikat %s, który nie jest certyfikatem urzędu certyfikacji (brak cA/keyCertSign) — ścieżka nieprawidłowa, możliwe fałszerstwo", cn(cur), cn(nonCA))
		}
		if next == nil {
			return chain, nil, pathErr(chain)
		}
		chain = append(chain, next)
		cur = next
	}
	return chain, nil, pathErr(chain)
}

func isCA(c *x509.Certificate) bool {
	return c.BasicConstraintsValid && c.IsCA && (c.KeyUsage == 0 || c.KeyUsage&x509.KeyUsageCertSign != 0)
}

// pathErr checks the leaf is not a CA and every CA's pathLenConstraint (RFC 5280 §4.2.1.9).
func pathErr(chain []*x509.Certificate) error {
	if len(chain) > 1 && chain[0].BasicConstraintsValid && chain[0].IsCA {
		return fmt.Errorf("certyfikat %s jest certyfikatem urzędu certyfikacji, a nie certyfikatem końcowym", cn(chain[0]))
	}
	for i, c := range chain[1:] { // i = number of intermediate CAs below c
		if (c.MaxPathLen > 0 || c.MaxPathLenZero) && i > c.MaxPathLen {
			return fmt.Errorf("przekroczone ograniczenie długości ścieżki (pathLenConstraint=%d) certyfikatu %s", c.MaxPathLen, cn(c))
		}
	}
	return nil
}

// findIssuer returns the CA that signed c; nonCA is set when only a non-CA certificate did.
func findIssuer(c *x509.Certificate, pool []*x509.Certificate) (issuer, nonCA *x509.Certificate) {
	for _, p := range pool {
		if !bytes.Equal(p.Raw, c.Raw) && bytes.Equal(p.RawSubject, c.RawIssuer) &&
			checkSigned(p, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
			if isCA(p) {
				return p, nil
			}
			nonCA = p
		}
	}
	return nil, nonCA
}
