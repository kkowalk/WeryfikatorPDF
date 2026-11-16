// Command weryfikator-podpisow checks whether PAdES signatures were valid at the
// signing date (not "now"). Documents never leave the machine; only CRL/OCSP/EU
// trusted-list requests derived from certificates go to the network.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

var version = "dev" // set at build time: -ldflags "-X main.version=..."

type check struct{ Name, State, Detail string }

func (c check) Label() string {
	return map[string]string{"ok": "OK", "fail": "BŁĄD", "unknown": "NIEROZSTRZYGNIĘTE", "warn": "UWAGA"}[c.State]
}

type dateCand struct {
	T                    time.Time
	Shown, Source, Level string
	rank                 int // 1 qualified sig TS, 2 qualified doc TS, 3/4 non-qualified, 5 signingTime, 6 /M, 99 manual
}

type certRow struct {
	Role, Name, ValidAtDate, File string
	Details                       []kv
}
type revRow struct {
	Cert, Kind, Source, File, Note, Result string
	Details                                []string
}
type tlRow struct{ Country, TSP, Service, Type, Status, File, URL string }

type sigReport struct {
	N                           int
	Kind, Signer, SignerDN      string
	Coverage, CoverageFile      string
	Dates                       []dateCand
	Date, DateSource, DateLevel string
	Qualified                   string
	Checks                      []check
	CMS                         []kv
	Timeline                    []tlEvent
	Chain                       []certRow
	Rev                         []revRow
	TL                          []tlRow
	Verdict, VerdictClass       string
	Notes                       []string  // certificate expiry/revocation, for the summary
	at                          time.Time // date the signature is evaluated at
}

func (s *sigReport) add(name, state, detail string) {
	s.Checks = append(s.Checks, check{name, state, detail})
}

type fileReport struct {
	Path, Name, SHA256, Error, Report string
	Embedded                          string
	Size                              int64
	Sigs                              []*sigReport
	Verdict, VerdictClass             string
}

type env struct {
	in    *bufio.Reader
	auto  bool
	ev    *evidence
	net   *netFetcher
	trust *trust
}

func main() { os.Exit(run()) }

func run() int {
	ask := flag.Bool("pytaj", false, "pytaj o datę każdego podpisu (domyślnie przyjmowana jest najsilniejsza data wykryta w podpisie)")
	noWait := flag.Bool("y", false, "nie czekaj na Enter na końcu (do skryptów)")
	outDir := flag.String("o", "", "katalog na raport (domyślnie: nowy katalog obok pierwszego pliku)")
	offline := flag.Bool("offline", false, "bez połączeń sieciowych (tylko dane osadzone w PDF; bez list zaufanych usług wynik będzie nierozstrzygający)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "weryfikator-podpisow %s — ważność podpisów PAdES na dzień podpisania\n\n"+
			"Użycie: weryfikator-podpisow.exe [-pytaj] [-y] [-offline] [-o katalog] plik.pdf|katalog ...\n"+
			"(można też przeciągnąć pliki lub katalog na ikonę programu)\n\n", version)
		flag.PrintDefaults()
	}
	flag.Parse()
	e := &env{in: bufio.NewReader(os.Stdin), auto: !*ask}
	if !*noWait {
		defer func() {
			fmt.Print("\nNaciśnij Enter, aby zakończyć...")
			e.in.ReadString('\n')
		}()
	}

	files := collect(flag.Args())
	if len(files) == 0 {
		flag.Usage()
		return 2
	}
	out := *outDir
	if out == "" {
		base := filepath.Dir(files[0])
		if st, err := os.Stat(flag.Arg(0)); err == nil && st.IsDir() {
			base = flag.Arg(0)
		}
		out = filepath.Join(base, "weryfikacja-podpisow-"+time.Now().Format("20060102-150405"))
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "Nie można utworzyć katalogu raportu:", err)
		return 1
	}
	e.ev = &evidence{dir: out, saved: map[[32]byte]string{}}
	e.net = &netFetcher{client: &http.Client{Timeout: 60 * time.Second}, ev: e.ev, cache: map[string]fetched{}, offline: *offline}
	if *offline {
		fmt.Println("Tryb offline: brak połączeń sieciowych.")
	} else {
		fmt.Println("Prywatność: dokumenty nie są wysyłane. Program pobiera listy zaufanych usług UE oraz CRL/OCSP\n" +
			"z adresów zapisanych w certyfikatach (zapytanie OCSP zawiera numer seryjny certyfikatu).\n" +
			"Szczegóły: PRIVACY.md. Opcja -offline wyłącza połączenia.")
	}
	e.trust = &trust{net: e.net, loaded: map[string]bool{}}

	var reports []*fileReport
	for i, f := range files {
		fmt.Printf("\n[%d/%d] %s\n", i+1, len(files), f)
		fr := e.analyzeFile(f)
		fr.Report = fmt.Sprintf("%03d-%s.html", i+1, safeName(strings.TrimSuffix(fr.Name, filepath.Ext(fr.Name))))
		if err := writeFileReport(out, fr); err != nil {
			fmt.Fprintln(os.Stderr, "Błąd zapisu raportu:", err)
			return 1
		}
		fmt.Println("  →", fr.Verdict)
		reports = append(reports, fr)
	}
	if err := writeIndex(out, reports, e); err != nil {
		fmt.Fprintln(os.Stderr, "Błąd zapisu raportu zbiorczego:", err)
		return 1
	}
	index := filepath.Join(out, "index.html")
	fmt.Println("\nRaport:", index)
	openBrowser(index)
	return 0
}

func collect(args []string) []string {
	var out []string
	for _, a := range args {
		st, err := os.Stat(a)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Pominięto:", err)
			continue
		}
		if !st.IsDir() {
			out = append(out, a)
			continue
		}
		filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && strings.HasPrefix(d.Name(), "weryfikacja-podpisow-") {
				return filepath.SkipDir // our own earlier reports
			}
			if !d.IsDir() && strings.EqualFold(filepath.Ext(p), ".pdf") {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}

func (e *env) analyzeFile(p string) *fileReport {
	fr := &fileReport{Path: p, Name: filepath.Base(p)}
	if abs, err := filepath.Abs(p); err == nil {
		fr.Path = abs
	}
	defer fr.finish()
	st, err := os.Stat(p)
	if err == nil && st.Size() > 1<<30 {
		err = errors.New("plik większy niż 1 GB")
	}
	var data []byte
	if err == nil {
		data, err = os.ReadFile(p)
	}
	if err != nil {
		fr.Error = "Nie można odczytać pliku: " + err.Error()
		return fr
	}
	h := sha256.Sum256(data)
	fr.Size, fr.SHA256 = int64(len(data)), hex.EncodeToString(h[:])

	sigs := findSignatures(data)
	if len(sigs) == 0 {
		fr.Error = "Nie znaleziono podpisów PDF (brak poprawnych /ByteRange)."
		return fr
	}
	pl := newPool()
	pl.harvestStreams(data)
	type item struct {
		ps  pdfSig
		c   *cmsSig
		err error
		ts  *tsResult
	}
	items := make([]item, len(sigs))
	for i, ps := range sigs {
		it := item{ps: ps}
		if ps.SubFilter == "ETSI.RFC3161" {
			it.ts = parseTimestamp(ps.DER, ps.Signed)
			for _, c := range it.ts.Certs {
				pl.addCert(c)
			}
		} else if it.c, it.err = parseCMS(ps.DER); it.err == nil {
			for _, c := range it.c.certs {
				pl.addCert(c)
			}
			if len(it.c.crlsRaw) > 0 {
				pl.harvest(it.c.crlsRaw, 0)
			}
			if v, ok := it.c.signed[oidAdbeRevInfo]; ok {
				pl.harvest(v.FullBytes, 0)
			}
		}
		items[i] = it
	}
	fr.Embedded = fmt.Sprintf("%d certyfikatów, %d CRL, %d odpowiedzi OCSP (z CMS i słownika DSS)", len(pl.certs), len(pl.crls), len(pl.ocsps))
	for _, c := range pl.certs {
		e.trust.load(country(c.Subject.Country))
		e.trust.load(country(c.Issuer.Country))
	}
	for i, it := range items {
		if it.ts != nil {
			fr.Sigs = append(fr.Sigs, e.evalDocTS(i+1, it.ps, it.ts, pl, data))
			continue
		}
		var covering []*tsResult // later document timestamps that cover this signature
		for _, o := range items {
			if o.ts != nil && o.ts.Err == nil && o.ps.End > it.ps.End {
				covering = append(covering, o.ts)
			}
		}
		fr.Sigs = append(fr.Sigs, e.evalSig(i+1, fr.Name, it.ps, it.c, it.err, covering, pl, data))
	}
	return fr
}

func country(c []string) string {
	if len(c) == 0 {
		return ""
	}
	return c[0]
}

func (fr *fileReport) finish() {
	fr.Verdict, fr.VerdictClass = "NIEROZSTRZYGNIĘTE", "unknown"
	if fr.Error != "" {
		return
	}
	rank := map[string]int{"ok": 0, "unknown": 1, "fail": 2}
	worst := ""
	for _, s := range fr.Sigs {
		if s.Kind == "Podpis" && (worst == "" || rank[s.VerdictClass] > rank[worst]) {
			worst = s.VerdictClass
		}
	}
	switch worst {
	case "ok":
		fr.Verdict, fr.VerdictClass = "WSZYSTKIE PODPISY WAŻNE NA DZIEŃ PODPISANIA", "ok"
	case "fail":
		fr.Verdict, fr.VerdictClass = "CO NAJMNIEJ JEDEN PODPIS NIEWAŻNY", "fail"
	case "":
		fr.Verdict = "BRAK PODPISÓW (tylko znaczniki czasu dokumentu)"
	}
}

func (s *sigReport) coverage(ps pdfSig, data []byte, ev *evidence) {
	if ps.End == int64(len(data)) {
		s.Coverage = "cały plik (bieżąca wersja)"
		return
	}
	s.Coverage = fmt.Sprintf("bajty 0–%d z %d — plik zmieniono po podpisaniu (aktualizacja przyrostowa)", ps.End, len(data))
	s.CoverageFile = ev.save("wersja-podpisana", "pdf", data[:ps.End])
	s.add("Zakres podpisu", "warn", "Po złożeniu podpisu do pliku dopisano zmiany (np. kolejne podpisy, adnotacje, znaczniki czasu). "+
		"Treść bieżącej wersji może różnić się od podpisanej — rozstrzyga zapisana wersja podpisana.")
}

// evalTS validates a timestamp's TSA and reports whether it is qualified at genTime.
func (e *env) evalTS(ts *tsResult, pl *pool) (level string, qualified bool, err error) {
	if ts.Err != nil {
		return "", false, ts.Err
	}
	if ts.GenTime.Before(ts.TSA.NotBefore) || ts.GenTime.After(ts.TSA.NotAfter) {
		return "", false, errors.New("certyfikat TSA nie był ważny w chwili wystawienia znacznika")
	}
	e.trust.load(country(ts.TSA.Subject.Country))
	e.trust.load(country(ts.TSA.Issuer.Country))
	// ponytail: TSA certificate revocation is not checked; qualified status comes from the TL.
	_, anchor := e.trust.chain(ts.TSA, slices.Concat(ts.Certs, pl.certs))
	for _, a := range anchor {
		st, ok := a.at(ts.GenTime)
		if ok && positive(st.Status) && (strings.HasSuffix(st.Type, "/TSA/QTST") ||
			(strings.HasSuffix(st.Type, "/TSA") && path.Base(st.Status) == "accredited")) {
			return fmt.Sprintf("kwalifikowany znacznik czasu — %s / %s (%s), status %s", a.TSP, a.Service, a.Country, path.Base(st.Status)), true, nil
		}
	}
	return "niekwalifikowany znacznik czasu (poprawny kryptograficznie) — TSA: " + cn(ts.TSA), false, nil
}

func (e *env) evalDocTS(n int, ps pdfSig, ts *tsResult, pl *pool, data []byte) *sigReport {
	s := &sigReport{N: n, Kind: "Znacznik czasu dokumentu"}
	if ts.TSA != nil {
		s.Signer, s.SignerDN = cn(ts.TSA), ts.TSA.Subject.String()
	}
	s.coverage(ps, data, e.ev)
	s.Date, s.DateSource = fmtTime(ts.GenTime), "TSTInfo.genTime"
	if level, _, err := e.evalTS(ts, pl); err != nil {
		s.add("Znacznik czasu", "fail", err.Error())
	} else {
		s.DateLevel = level
		s.add("Znacznik czasu", "ok", "Token RFC 3161 poprawny i obejmuje dokument w zakresie ByteRange — dowód, że ta wersja dokumentu istniała najpóźniej "+s.Date+".")
	}
	_, cls := verdict(s.Checks)
	s.Verdict, s.VerdictClass = map[string]string{"ok": "ZNACZNIK CZASU POPRAWNY", "fail": "ZNACZNIK CZASU NIEPOPRAWNY"}[cls], cls
	return s
}

func (e *env) evalSig(n int, fname string, ps pdfSig, c *cmsSig, perr error, docTS []*tsResult, pl *pool, data []byte) *sigReport {
	s := &sigReport{N: n, Kind: "Podpis"}
	s.coverage(ps, data, e.ev)
	if perr != nil {
		s.add("Struktura podpisu", "fail", perr.Error())
		s.finish(dateCand{})
		return s
	}
	signer := c.signer
	s.Signer, s.SignerDN = cn(signer), signer.Subject.String()
	s.CMS = cmsDetails(ps, c)

	if err := c.verify(ps.Signed); err != nil {
		s.add("Integralność i podpis kryptograficzny", "fail", err.Error())
	} else {
		s.add("Integralność i podpis kryptograficzny", "ok", "Skrót zakresu ByteRange zgodny z messageDigest; podpis zweryfikowany kluczem publicznym certyfikatu podpisującego.")
	}
	if present, err := c.checkESS(); err != nil {
		s.add("Powiązanie certyfikatu z podpisem", "fail", err.Error())
	} else if !present {
		s.add("Powiązanie certyfikatu z podpisem", "warn", "Brak atrybutu signing-certificate(-v2) wymaganego w PAdES — certyfikat nie jest chroniony podpisem.")
	} else {
		s.add("Powiązanie certyfikatu z podpisem", "ok", "Skrót certyfikatu w atrybucie signing-certificate zgodny.")
	}
	if ku := signer.KeyUsage; ku != 0 && ku&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		s.add("Przeznaczenie klucza", "fail", "keyUsage certyfikatu nie dopuszcza składania podpisu.")
	}

	// Date candidates, strongest first.
	var cands []dateCand
	var sigTS time.Time
	if v, ok := c.unsigned[oidSigTimestamp]; ok {
		ts := parseTimestamp(firstValue(v), c.si.Signature)
		if level, q, err := e.evalTS(ts, pl); err != nil {
			s.add("Znacznik czasu podpisu", "warn", "Pominięty: "+err.Error())
		} else {
			cands = append(cands, dateCand{T: ts.GenTime, Source: "znacznik czasu podpisu — podpis istniał najpóźniej w tej chwili", Level: level, rank: map[bool]int{true: 1, false: 3}[q]})
			sigTS = ts.GenTime
		}
	}
	for _, d := range docTS {
		if level, q, err := e.evalTS(d, pl); err == nil {
			cands = append(cands, dateCand{T: d.GenTime, Source: "znacznik czasu dokumentu obejmujący podpis — podpis istniał najpóźniej w tej chwili", Level: level, rank: map[bool]int{true: 2, false: 4}[q]})
			break
		}
	}
	const claimed = "deklaracja podpisującego (zegar komputera podpisującego) — bez dowodu kryptograficznego"
	if t, ok := c.signingTime(); ok {
		cands = append(cands, dateCand{T: t, Source: "atrybut signingTime w podpisie", Level: claimed, rank: 5})
	}
	if !ps.M.IsZero() {
		cands = append(cands, dateCand{T: ps.M, Source: "pole /M słownika podpisu PDF", Level: claimed, rank: 6})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].rank < cands[j].rank })
	for i := range cands {
		cands[i].Shown = fmtTime(cands[i].T)
	}
	s.Dates = cands

	d := e.askDate(fname, n, s.Signer, cands)
	if d.T.IsZero() {
		s.add("Data podpisania", "unknown", "Brak daty w podpisie i nie podano jej ręcznie.")
		s.finish(d)
		return s
	}
	S := d.T
	s.at = S
	s.Date, s.DateSource, s.DateLevel = d.Shown, d.Source, d.Level
	s.event(S, "PRZYJĘTA DATA PODPISU — "+d.Source, d.Level, evSign)
	for _, cd := range cands {
		if cd.rank != d.rank {
			s.event(cd.T, "Data podpisu wg: "+cd.Source, cd.Level, "")
		}
	}
	if !sigTS.IsZero() && S.After(sigTS) {
		s.add("Spójność daty", "warn", "Przyjęta data jest późniejsza niż znacznik czasu podpisu ("+fmtTime(sigTS)+"), a podpis istniał już w chwili znacznika.")
	}

	chain, anchor := e.trust.chain(signer, pl.certs)
	for i, ct := range chain {
		role := "pośredni"
		switch {
		case i == 0:
			role = "podpisujący"
		case i == len(chain)-1 && anchor != nil:
			role = "wystawca z listy zaufanych usług"
		}
		valid := !S.Before(ct.NotBefore) && !S.After(ct.NotAfter)
		s.Chain = append(s.Chain, certRow{role, cn(ct), map[bool]string{true: "tak", false: "NIE"}[valid], e.ev.save("cert", "cer", ct.Raw), certDetails(ct)})
		src := "certyfikat " + cn(ct) + ", nr " + ct.SerialNumber.Text(16)
		s.event(ct.NotBefore, "Początek ważności certyfikatu: "+cn(ct), src, evStart)
		s.event(ct.NotAfter, "Koniec ważności certyfikatu: "+cn(ct), src, evStop)
		if ct.NotAfter.Before(time.Now()) {
			s.Notes = append(s.Notes, fmt.Sprintf("Certyfikat %s wygasł %s (%s)", cn(ct), fmtTime(ct.NotAfter), relTo(ct.NotAfter, S)))
		}
		if valid {
			s.add("Okres ważności: "+cn(ct), "ok", fmt.Sprintf("Ważny od %s do %s. Data podpisu przypada %s po początku i %s przed końcem ważności.",
				fmtTime(ct.NotBefore), fmtTime(ct.NotAfter), fmtDelta(S.Sub(ct.NotBefore)), fmtDelta(ct.NotAfter.Sub(S))))
		} else {
			s.add("Okres ważności: "+cn(ct), "fail", "Certyfikat ważny "+fmtTime(ct.NotBefore)+" — "+fmtTime(ct.NotAfter)+"; nie obejmuje daty podpisu.")
		}
	}
	if anchor == nil {
		s.add("Kotwica zaufania (lista zaufanych usług UE)", "unknown",
			"Nie zbudowano ścieżki certyfikacji do usługi z listy zaufanych usług państwa UE. "+strings.Join(e.trust.Errors, " "))
		s.Qualified = "NIEUSTALONY — brak powiązania z listą zaufanych usług"
		s.finish(d)
		return s
	}
	s.add("Kotwica zaufania (lista zaufanych usług UE)", "ok", fmt.Sprintf("%s — %s (%s)", anchor[0].TSP, anchor[0].Service, anchor[0].Country))
	for _, a := range anchor {
		row := tlRow{Country: a.Country, TSP: a.TSP, Service: a.Service, Type: "—", Status: "brak wpisu na tę datę", File: a.File, URL: a.URL}
		if st, ok := a.at(S); ok {
			row.Type = strings.TrimPrefix(st.Type, "http://uri.etsi.org/TrstSvc/Svctype/")
			row.Status = path.Base(st.Status) + " (od " + fmtTime(st.Start) + ")"
			s.event(st.Start, "Usługa „"+a.Service+"” ("+row.Type+") ze statusem "+path.Base(st.Status)+" na liście zaufanych usług", a.URL, "")
		}
		s.TL = append(s.TL, row)
	}

	for i := 0; i < len(chain)-1; i++ {
		evs, st, dec := checkRevocation(chain[i], chain[i+1], S, pl, e.net, e.ev)
		for _, r := range evs {
			s.Rev = append(s.Rev, revRow{cn(chain[i]), r.Kind, r.Source, r.File, r.Note, r.Status.String(), revDetails(r, chain[i])})
		}
		name := "Status unieważnienia: " + cn(chain[i])
		if dec != nil {
			label := dec.Kind
			if dec.Number != "" {
				label += " nr " + dec.Number
			}
			s.event(dec.ThisUpdate, "Wydanie dowodu statusu ("+label+") dla: "+cn(chain[i]), dec.Source, evEvidence)
			s.event(dec.RevokedAt, "Unieważnienie certyfikatu: "+cn(chain[i])+" — powód: "+reasons[dec.Reason], label+", "+dec.Source, evRevoke)
			s.event(dec.Invalidity, "Wskazana data utraty ważności klucza (invalidityDate): "+cn(chain[i]), label+", "+dec.Source, evRevoke)
			if !dec.RevokedAt.IsZero() {
				s.Notes = append(s.Notes, fmt.Sprintf("Certyfikat %s unieważniony %s (%s), powód: %s", cn(chain[i]), fmtTime(dec.RevokedAt), relTo(dec.RevokedAt, S), reasons[dec.Reason]))
			}
		}
		switch st {
		case revRevoked:
			s.add(name, "fail", dec.Note+" ("+dec.Kind+", "+dec.Source+")")
		case revGood:
			detail := dec.Note + " (" + dec.Kind + " z " + fmtTime(dec.ThisUpdate) + ", " + dec.Source + "; nr seryjny " + chain[i].SerialNumber.Text(16) + ")"
			if !dec.RevokedAt.IsZero() {
				detail += fmt.Sprintf(". Unieważnienie nastąpiło %s po podpisie; certyfikat traci ważność dopiero z chwilą unieważnienia (art. 28 ust. 4 eIDAS), więc w chwili podpisu był ważny.", fmtDelta(dec.RevokedAt.Sub(S)))
			}
			s.add(name, "ok", detail)
			if !dec.Invalidity.IsZero() && !dec.Invalidity.After(S) {
				s.add("Data utraty ważności klucza", "warn", "Wystawca wskazał invalidityDate "+fmtTime(dec.Invalidity)+
					" — wcześniejszą niż data podpisu. Certyfikat traci ważność z chwilą unieważnienia (eIDAS art. 28 ust. 4), ale okoliczność ta może podważać wiarygodność podpisu.")
			}
			if !dec.RevokedAt.IsZero() && dec.Reason == 1 && d.rank > 4 {
				s.add("Ryzyko antydatowania", "warn", "Certyfikat unieważniono z powodu kompromitacji klucza, a data podpisu nie jest potwierdzona znacznikiem czasu.")
			}
		default:
			s.add(name, "unknown", "Brak rozstrzygających danych o unieważnieniu na dzień podpisu (szczegóły w tabeli dowodów).")
		}
	}
	s.Qualified = qualification(signer, anchor, S)
	s.finish(d)
	return s
}

func (s *sigReport) finish(d dateCand) {
	if len(s.Timeline) > 0 {
		s.event(time.Now(), "Sporządzenie raportu", tool(), evEvidence)
		s.sortTimeline()
	}
	_, cls := verdict(s.Checks)
	s.VerdictClass = cls
	switch cls {
	case "fail":
		s.Verdict = "PODPIS NIEWAŻNY"
		if s.Date != "" {
			s.Verdict += " NA DZIEŃ " + s.Date
		}
	case "unknown":
		s.Verdict = "NIEROZSTRZYGNIĘTE"
	default:
		s.Verdict = "PODPIS WAŻNY NA DZIEŃ " + s.Date
		if d.rank > 4 {
			s.Verdict += " — pod warunkiem, że podpis złożono w tej dacie (data niepotwierdzona znacznikiem czasu)"
		}
	}
}

func verdict(cs []check) (string, string) {
	cls := "ok"
	for _, c := range cs {
		switch c.State {
		case "fail":
			return "fail", "fail"
		case "unknown":
			cls = "unknown"
		}
	}
	return cls, cls
}

func qualification(signer *x509.Certificate, anchor []*tlEntry, S time.Time) string {
	comp, sscd, seal := false, false, false
	for _, x := range signer.Extensions {
		if x.Id.String() != "1.3.6.1.5.5.7.1.3" {
			continue
		}
		var sts []struct {
			ID   asn1.ObjectIdentifier
			Info asn1.RawValue `asn1:"optional"`
		}
		asn1.Unmarshal(x.Value, &sts)
		for _, st := range sts {
			switch st.ID.String() {
			case "0.4.0.1862.1.1":
				comp = true
			case "0.4.0.1862.1.4":
				sscd = true
			case "0.4.0.1862.1.6":
				var types []asn1.ObjectIdentifier
				asn1.Unmarshal(st.Info.FullBytes, &types)
				for _, t := range types {
					seal = seal || t.String() == "0.4.0.1862.1.6.2"
				}
			}
		}
	}
	caQC := false
	for _, a := range anchor {
		if st, ok := a.at(S); ok && positive(st.Status) && strings.HasSuffix(st.Type, "/CA/QC") {
			caQC = true
		}
	}
	const note = " (kwalifikatory z listy zaufanych usług nie są uwzględniane)"
	q, adv := "kwalifikowany podpis elektroniczny", "zaawansowany podpis elektroniczny"
	if seal {
		q, adv = "kwalifikowana pieczęć elektroniczna", "zaawansowana pieczęć elektroniczna"
	}
	switch {
	case !comp:
		return "NIE — certyfikat nie deklaruje statusu kwalifikowanego (brak QcCompliance)"
	case !caQC:
		return "NIE — wystawca nie miał na dzień podpisu statusu kwalifikowanego (CA/QC) na liście zaufanych usług"
	case sscd:
		return "TAK — " + q + ": certyfikat kwalifikowany wydany przez kwalifikowanego dostawcę + deklaracja QSCD" + note
	}
	return "CZĘŚCIOWO — " + adv + " oparty na certyfikacie kwalifikowanym, bez deklaracji QSCD" + note
}

func (e *env) askDate(fname string, n int, signer string, cands []dateCand) dateCand {
	fmt.Printf("\n  %s — podpis #%d: %s\n", fname, n, signer)
	for _, c := range cands {
		fmt.Printf("    %s  %s\n      [%s]\n", c.Shown, c.Source, c.Level)
	}
	if e.auto {
		if len(cands) > 0 {
			return cands[0]
		}
		return dateCand{}
	}
	for {
		if len(cands) > 0 {
			fmt.Printf("  Data do oceny: %s\n  Enter = akceptuj, albo wpisz inną (RRRR-MM-DD GG:MM[:SS], czas lokalny): ", cands[0].Shown)
		} else {
			fmt.Print("  Brak daty w podpisie. Wpisz RRRR-MM-DD GG:MM[:SS] (czas lokalny) albo Enter, aby pominąć: ")
		}
		line, err := e.in.ReadString('\n')
		line = strings.TrimSpace(strings.TrimLeft(line, string(rune(0xFEFF)))) // BOM from PowerShell pipes
		if line == "" {
			if len(cands) > 0 {
				return cands[0]
			}
			return dateCand{}
		}
		for _, l := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02T15:04:05", "2006-01-02T15:04"} {
			if t, perr := time.ParseInLocation(l, line, time.Local); perr == nil {
				return dateCand{T: t, Shown: fmtTime(t), Source: "podana ręcznie przez użytkownika",
					Level: "oświadczenie użytkownika — bez dowodu kryptograficznego", rank: 99}
			}
		}
		fmt.Println("  Nieprawidłowy format daty.")
		if err != nil {
			return dateCand{}
		}
	}
}

func cn(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05 -07:00")
}
