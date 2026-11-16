# WeryfikatorPDF

Narzędzie konsolowe (pojedynczy `.exe`, bez instalacji i uprawnień administratora), które sprawdza,
czy podpisy **PAdES** w plikach PDF były ważne **na dzień ich złożenia** — a nie na dzień weryfikacji.

Typowe walidatory oceniają podpis „na teraz”. Po wygaśnięciu lub unieważnieniu certyfikatu, przy braku
danych LTV, zwracają wynik nierozstrzygający lub negatywny, choć w chwili podpisania podpis był ważny.

## Prywatność

Dokumenty **nie są nigdzie wysyłane**. Z sieci pobierane są wyłącznie:
- unijna lista LOTL i krajowe listy zaufanych usług (HTTPS),
- listy CRL i odpowiedzi OCSP z adresów zapisanych w certyfikatach, i tylko dla łańcuchów zakotwiczonych
  na liście zaufanych usług. Zapytanie OCSP zawiera numer seryjny certyfikatu.

Opcja `-offline` wyłącza wszystkie połączenia. Szczegóły: [polityka prywatności](PRIVACY.md).

## Użycie

Przeciągnij pliki PDF lub katalog na `weryfikator-podpisow.exe`, albo:

```
weryfikator-podpisow.exe [-y] [-o katalog_raportu] plik.pdf katalog\ ...
```

| Opcja | Znaczenie |
|---|---|
| `-y` | przyjmij daty wykryte w podpisach bez pytania; nie czekaj na Enter na końcu |
| `-o` | katalog raportu (domyślnie `weryfikacja-podpisow-<data>` obok pierwszego pliku) |
| `-offline` | bez połączeń sieciowych; wynik będzie nierozstrzygający, bo nie da się wtedy sprawdzić list zaufanych usług |

Gotowy plik `.exe` pobierzesz z [Releases](../../releases). Sprawdź [Code signing policy](#code-signing-policy).

Dla każdego podpisu program pokazuje wykryte daty od najsilniejszego dowodu. Enter przyjmuje proponowaną
datę. Można też wpisać inną datę (`RRRR-MM-DD GG:MM[:SS]`, czas lokalny), np. gdy użytkownik wie, kiedy
plik podpisano.

Wynik:
- `index.html` — zestawienie zbiorcze i log zapytań sieciowych,
- `NNN-<plik>.html` — raport dla każdego pliku (do druku lub zapisu do PDF jako załącznik do akt),
- `podsumowanie.csv` — UTF-8, separator `;`,
- `dowody/` — kopie użytych certyfikatów, CRL, OCSP i list zaufanych usług, a przy zmianach po podpisaniu
  także wersja PDF, którą faktycznie podpisano.

## Metodyka

Ocena na dzień podpisu S:
1. **Integralność**: skrót zakresu ByteRange musi być zgodny z `messageDigest`, podpis musi dać się
   zweryfikować kluczem certyfikatu, a atrybut `signing-certificate(-v2)` musi wiązać certyfikat z podpisem.
2. **Data S** jest wybierana według siły dowodowej: kwalifikowany znacznik czasu > niekwalifikowany znacznik
   czasu (podpisu lub dokumentu) > `signingTime` / `/M` (deklaracja podpisującego) > data podana ręcznie.
   Gdy data nie jest potwierdzona znacznikiem czasu, wynik „ważny” jest warunkowy.
3. **Ścieżka certyfikacji** musi prowadzić do usługi z listy zaufanych usług państwa UE
   ([ETSI TS 119 612](https://www.etsi.org/standards)), a S musi mieścić się w okresie ważności
   każdego certyfikatu.
4. **Unieważnienie**: źródła w kolejności dane osadzone w PDF (DSS, `adbe-revocationInfoArchival`),
   CRL ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)), OCSP
   ([RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)).
   - Unieważnienie po S oznacza, że certyfikat był ważny w chwili podpisu. Certyfikat traci ważność
     z chwilą unieważnienia, zgodnie z art. 28 ust. 4
     [eIDAS](https://eur-lex.europa.eu/eli/reg/2014/910/oj).
   - CRL lub OCSP wydane przed S nie są dowodem.
   - Brak wpisu na CRL wydanej po wygaśnięciu certyfikatu daje wynik nierozstrzygający, bo wpis mógł
     zostać usunięty (RFC 5280 §3.3).
5. **Status kwalifikowany** wynika z QcStatements w certyfikacie oraz statusu CA/QC wystawcy na liście
   zaufanych usług na dzień S, z uwzględnieniem historii statusów (art. 32 ust. 1 eIDAS).

## Ograniczenia

- Podpisy XML list zaufanych usług nie są weryfikowane. Integralność zapewnia HTTPS ze źródeł wskazanych w LOTL.
- Kwalifikatory usług (`ServiceInformationExtensions`) nie są uwzględniane.
- Nie jest sprawdzane unieważnienie certyfikatów TSA ani delegowanych responderów OCSP.
- Nie jest analizowane DocMDP. Wykrywane są tylko zmiany dopisane poza zakresem podpisu.
- Podpis CMS musi być zakodowany w DER (BER nie jest obsługiwany).
- Proxy: Go nie korzysta z systemowego proxy Windows. W razie potrzeby ustaw zmienną `HTTPS_PROXY`.
- Obsługiwany jest tylko format PAdES (bez XAdES i CAdES).

## Budowanie

Wymaga Go ≥ 1.27.

```
go test ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o weryfikator-podpisow.exe .
```

Niepodpisany `.exe` może zostać zatrzymany przez SmartScreen lub AppLocker. Do dystrybucji warto podpisać
plik certyfikatem do podpisywania kodu.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

Podpisywane są wyłącznie pliki `weryfikator-podpisow.exe` zbudowane z kodu tego repozytorium przez
[workflow release](.github/workflows/release.yml) na runnerach GitHub. Każde podpisanie wymaga ręcznego zatwierdzenia.

| Rola | Osoby |
|---|---|
| Autorzy (committers) | [@kkowalk](https://github.com/kkowalk) |
| Recenzenci (reviewers) | [@kkowalk](https://github.com/kkowalk) |
| Zatwierdzający (approvers) | [@kkowalk](https://github.com/kkowalk) |

Wszyscy członkowie zespołu używają uwierzytelniania wieloskładnikowego w GitHub i SignPath.
Prywatność: [PRIVACY.md](PRIVACY.md).

Weryfikacja pobranego pliku: podpis Authenticode (Właściwości → Podpisy cyfrowe), suma z `SHA256SUMS` oraz
`gh attestation verify weryfikator-podpisow.exe --repo kkowalk/WeryfikatorPDF`.

## Licencja

[MIT](LICENSE)
