package main

import (
	"encoding/csv"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const css = `body{font:14px/1.45 system-ui,Segoe UI,sans-serif;color:#1d1d1f;background:#fff;max-width:1100px;margin:24px auto;padding:0 16px}
h1{font-size:22px}h2{font-size:18px;margin-top:32px;border-top:1px solid #ccc;padding-top:16px}h3{font-size:15px;margin-top:20px}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}
th{background:#f4f4f6}.kv th{width:220px}.mono{font-family:Consolas,monospace;word-break:break-all}
.verdict{font-weight:700;font-size:16px;padding:10px 14px;border-radius:6px}
.verdict.ok{background:#e3f4e6;color:#14532d}.verdict.fail{background:#fde4e4;color:#7f1d1d}.verdict.unknown{background:#fff4d6;color:#713f12}
tr.fail td:nth-child(2){color:#b91c1c;font-weight:700}tr.ok td:nth-child(2){color:#15803d;font-weight:700}
tr.unknown td:nth-child(2),tr.warn td:nth-child(2){color:#a16207;font-weight:700}
.small{font-size:12px;color:#555}h4{font-size:14px;margin:14px 0 4px}
.tl td:first-child{border-left:6px solid transparent}
.tl tr.sign td{background:#dbeafe;font-weight:700}.tl tr.sign td:first-child{border-left-color:#1d4ed8}
.tl tr.start td{background:#ecfdf3}.tl tr.start td:first-child{border-left-color:#16a34a}
.tl tr.stop td{background:#fff7ed}.tl tr.stop td:first-child{border-left-color:#ea580c}
.tl tr.revoke td{background:#fef2f2;font-weight:700}.tl tr.revoke td:first-child{border-left-color:#dc2626}
.tl tr.evidence td{color:#555}
.lg span{display:inline-block;padding:1px 8px;margin-right:6px;border-left:6px solid}
.lg .sign{background:#dbeafe;border-color:#1d4ed8}.lg .start{background:#ecfdf3;border-color:#16a34a}
.lg .stop{background:#fff7ed;border-color:#ea580c}.lg .revoke{background:#fef2f2;border-color:#dc2626}
.note{color:#9a3412}
ul.ev{margin:0;padding-left:16px}@media print{*{print-color-adjust:exact;-webkit-print-color-adjust:exact}a{color:inherit}h2{break-before:page}}`

const methodology = `<h2>Metodyka i ograniczenia</h2>
<ul class="small">
<li>Ocena dotyczy stanu <b>na dzień podpisania</b> (dzień oceny podany w raporcie), nie na dzień sporządzenia raportu.
Kryteria: art. 32 ust. 1 rozporządzenia eIDAS (UE) nr 910/2014; utrata ważności certyfikatu z chwilą unieważnienia — art. 28 ust. 4 eIDAS
(<a href="https://eur-lex.europa.eu/eli/reg/2014/910/oj">EUR-Lex</a>); procedura walidacji wzorowana na ETSI EN 319 102-1; listy zaufanych usług wg ETSI TS 119 612; CRL wg RFC 5280; OCSP wg RFC 6960.</li>
<li>Siła dowodowa daty: kwalifikowany znacznik czasu &gt; niekwalifikowany znacznik czasu &gt; deklaracja podpisującego (signingTime, /M) &gt; data podana ręcznie.
Znacznik czasu dowodzi, że podpis istniał <i>najpóźniej</i> w chwili znacznika. Data podana ręcznie to oświadczenie użytkownika — wynik „ważny” jest wtedy warunkowy.</li>
<li>Dokument nie był nigdzie wysyłany. Z sieci pobrano wyłącznie listy zaufanych usług (LOTL i krajowe), listy CRL oraz odpowiedzi OCSP (zapytanie OCSP zawiera numer seryjny certyfikatu).
Wszystkie wykorzystane dane zapisano w katalogu <span class="mono">dowody/</span> — można je zweryfikować niezależnie.</li>
<li>Ograniczenia wersji: podpisy XML list zaufanych usług nie są weryfikowane (integralność zapewnia HTTPS ze źródeł wskazanych w LOTL);
kwalifikatory usług (ServiceInformationExtensions) nie są uwzględniane; nie jest sprawdzany status unieważnienia certyfikatów TSA i delegowanych responderów OCSP;
nie jest analizowane uprawnienie do zmian po podpisaniu (DocMDP) — wykrywane są jedynie zmiany poza zakresem podpisu; obsługiwane jest kodowanie DER podpisu CMS.</li>
</ul>`

var fileTpl = template.Must(template.New("f").Parse(`<!doctype html><html lang="pl"><head><meta charset="utf-8">
<title>Weryfikacja — {{.F.Name}}</title><style>` + css + `</style></head><body>
<p class="small"><a href="index.html">← raport zbiorczy</a></p>
<h1>Weryfikacja podpisów na dzień podpisania</h1>
<p class="verdict {{.F.VerdictClass}}">{{.F.Verdict}}</p>
<table class="kv">
<tr><th>Plik</th><td>{{.F.Name}}</td></tr>
<tr><th>Ścieżka</th><td class="mono">{{.F.Path}}</td></tr>
<tr><th>Rozmiar</th><td>{{.F.Size}} B</td></tr>
<tr><th>SHA-256 pliku</th><td class="mono">{{.F.SHA256}}</td></tr>
{{if .F.Embedded}}<tr><th>Dane osadzone w pliku</th><td>{{.F.Embedded}}</td></tr>{{end}}
<tr><th>Raport wygenerowano</th><td>{{.Gen}} — {{.Tool}}</td></tr>
</table>
{{if .F.Error}}<p class="verdict unknown">{{.F.Error}}</p>{{end}}
{{range .F.Sigs}}
<h2>{{.Kind}} #{{.N}}{{if .Signer}} — {{.Signer}}{{end}}</h2>
<p class="verdict {{.VerdictClass}}">{{.Verdict}}</p>
<table class="kv">
<tr><th>Data, na którą oceniono</th><td>{{.Date}}</td></tr>
<tr><th>Źródło daty</th><td>{{.DateSource}}</td></tr>
<tr><th>Siła dowodowa daty</th><td>{{.DateLevel}}</td></tr>
{{if .Qualified}}<tr><th>Status kwalifikowany</th><td>{{.Qualified}}</td></tr>{{end}}
{{if .Notes}}<tr><th>Wygaśnięcie / unieważnienie</th><td class="note">{{range .Notes}}{{.}}<br>{{end}}</td></tr>{{end}}
{{if .SignerDN}}<tr><th>Podmiot certyfikatu</th><td>{{.SignerDN}}</td></tr>{{end}}
<tr><th>Zakres podpisu</th><td>{{.Coverage}}{{if .CoverageFile}} — <a href="{{.CoverageFile}}">wersja podpisana</a>{{end}}</td></tr>
</table>
{{if .Dates}}<h3>Daty wykryte w podpisie</h3>
<table><tr><th>Data</th><th>Źródło</th><th>Siła dowodowa</th></tr>
{{range .Dates}}<tr><td>{{.Shown}}</td><td>{{.Source}}</td><td>{{.Level}}</td></tr>{{end}}</table>{{end}}
<h3>Kontrole</h3>
<table><tr><th>Kontrola</th><th>Wynik</th><th>Szczegóły</th></tr>
{{range .Checks}}<tr class="{{.State}}"><td>{{.Name}}</td><td>{{.Label}}</td><td>{{.Detail}}</td></tr>{{end}}</table>
{{if .Timeline}}<h3>Oś czasu</h3>
<p class="small lg"><span class="start">początek ważności</span><span class="sign">podpis</span><span class="stop">koniec ważności</span><span class="revoke">unieważnienie</span></p>
<table class="tl"><tr><th>Data</th><th>Względem podpisu</th><th>Zdarzenie</th><th>Źródło</th></tr>
{{range .Timeline}}<tr class="{{.Kind}}"><td>{{.When}}</td><td>{{.Rel}}</td><td>{{.What}}</td><td class="small">{{.Src}}</td></tr>{{end}}</table>{{end}}
{{if .CMS}}<h3>Szczegóły podpisu (CMS)</h3>
<table class="kv">{{range .CMS}}<tr><th>{{.K}}</th><td class="mono">{{.V}}</td></tr>{{end}}</table>{{end}}
{{if .Chain}}<h3>Ścieżka certyfikacji</h3>
{{range .Chain}}<h4>{{.Role}}: {{.Name}} — ważny w dniu oceny: {{.ValidAtDate}}{{if .File}} — <a href="{{.File}}">plik .cer</a>{{end}}</h4>
<table class="kv">{{range .Details}}<tr><th>{{.K}}</th><td>{{.V}}</td></tr>{{end}}</table>{{end}}{{end}}
{{if .TL}}<h3>Lista zaufanych usług — status na dzień oceny</h3>
<table><tr><th>Kraj</th><th>Dostawca</th><th>Usługa</th><th>Typ</th><th>Status</th><th>Źródło</th></tr>
{{range .TL}}<tr><td>{{.Country}}</td><td>{{.TSP}}</td><td>{{.Service}}</td><td>{{.Type}}</td><td>{{.Status}}</td><td><span class="mono small">{{.URL}}</span>{{if .File}} — <a href="{{.File}}">kopia</a>{{end}}</td></tr>{{end}}</table>{{end}}
{{if .Rev}}<h3>Dowody statusu unieważnienia</h3>
<table><tr><th>Certyfikat</th><th>Rodzaj</th><th>Źródło</th><th>Szczegóły</th><th>Wynik</th><th>Uwagi</th></tr>
{{range .Rev}}<tr><td>{{.Cert}}</td><td>{{.Kind}}</td><td class="mono small">{{.Source}}{{if .File}} — <a href="{{.File}}">kopia</a>{{end}}</td>
<td class="small"><ul class="ev">{{range .Details}}<li>{{.}}</li>{{end}}</ul></td><td>{{.Result}}</td><td>{{.Note}}</td></tr>{{end}}</table>{{end}}
{{end}}
` + methodology + `</body></html>`))

var indexTpl = template.Must(template.New("i").Parse(`<!doctype html><html lang="pl"><head><meta charset="utf-8">
<title>Weryfikacja podpisów — raport zbiorczy</title><style>` + css + `</style></head><body>
<h1>Weryfikacja podpisów na dzień podpisania — raport zbiorczy</h1>
<p class="small">Wygenerowano {{.Gen}} — {{.Tool}}. Zestawienie CSV: <a href="podsumowanie.csv">podsumowanie.csv</a></p>
<table><tr><th>Plik</th><th>Wynik</th><th>Podpisy</th></tr>
{{range .Files}}<tr class="{{.VerdictClass}}"><td><a href="{{.Report}}">{{.Name}}</a><br><span class="mono small">{{.SHA256}}</span></td><td>{{.Verdict}}{{if .Error}}<br>{{.Error}}{{end}}</td>
<td>{{range .Sigs}}#{{.N}} {{.Kind}}: {{.Signer}} — {{.Date}} — <b>{{.Verdict}}</b><br>{{range .Notes}}<span class="small note">↳ {{.}}</span><br>{{end}}{{end}}</td></tr>{{end}}</table>
{{if .TrustErrors}}<h3>Problemy z listami zaufanych usług</h3><ul>{{range .TrustErrors}}<li>{{.}}</li>{{end}}</ul>{{end}}
<h3>Zapytania sieciowe</h3>
<table><tr><th>Czas</th><th>Metoda</th><th>URL</th><th>Wynik</th><th>Kopia</th></tr>
{{range .Log}}<tr><td>{{.When}}</td><td>{{.Method}}</td><td class="mono small">{{.URL}}</td><td>{{.Result}}</td><td>{{if .File}}<a href="{{.File}}">plik</a>{{end}}</td></tr>{{end}}</table>
` + methodology + `</body></html>`))

func tool() string { return "weryfikator-podpisow " + version }

func writeFileReport(dir string, fr *fileReport) error {
	f, err := os.Create(filepath.Join(dir, fr.Report))
	if err != nil {
		return err
	}
	defer f.Close()
	return fileTpl.Execute(f, map[string]any{"F": fr, "Gen": fmtTime(time.Now()), "Tool": tool()})
}

func writeIndex(dir string, frs []*fileReport, e *env) error {
	f, err := os.Create(filepath.Join(dir, "index.html"))
	if err != nil {
		return err
	}
	defer f.Close()
	if err := indexTpl.Execute(f, map[string]any{"Files": frs, "Gen": fmtTime(time.Now()), "Tool": tool(),
		"Log": e.net.Log, "TrustErrors": e.trust.Errors}); err != nil {
		return err
	}
	return writeCSV(filepath.Join(dir, "podsumowanie.csv"), frs)
}

// writeCSV: UTF-8 BOM and ';' for Polish Excel; cells neutralised against formula injection.
func writeCSV(name string, frs []*fileReport) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString(string(rune(0xFEFF)))
	w := csv.NewWriter(f)
	w.Comma = ';'
	w.Write([]string{"plik", "sha256", "wynik_pliku", "nr", "rodzaj", "podpisujacy", "data_oceny", "zrodlo_daty", "sila_dowodowa_daty", "wynik", "kwalifikowany", "wygasniecie_uniewaznienie"})
	for _, fr := range frs {
		if len(fr.Sigs) == 0 {
			w.Write(cells(fr.Path, fr.SHA256, fr.Verdict+" "+fr.Error, "", "", "", "", "", "", "", "", ""))
		}
		for _, s := range fr.Sigs {
			w.Write(cells(fr.Path, fr.SHA256, fr.Verdict, strconv.Itoa(s.N), s.Kind, s.Signer, s.Date, s.DateSource, s.DateLevel, s.Verdict, s.Qualified, strings.Join(s.Notes, "; ")))
		}
	}
	w.Flush()
	return w.Error()
}

func cells(v ...string) []string {
	for i, s := range v {
		if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
			v[i] = "'" + s
		}
	}
	return v
}

func safeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?*`, r) || r < 32 {
			return '_'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
}

func openBrowser(p string) {
	if runtime.GOOS == "windows" {
		exec.Command("rundll32", "url.dll,FileProtocolHandler", p).Start()
	}
}
