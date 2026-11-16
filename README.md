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

### Okno programu (Windows)

Dwuklik na `weryfikator-podpisow.exe` albo przeciągnięcie plików lub folderów na jego ikonę otwiera okno programu
(natywne Win32, bez instalacji i bez nasłuchu sieciowego). W oknie można:
- dodawać pliki przeciągnięciem lub przyciskami „Dodaj pliki…” / „Dodaj folder…”,
- zaznaczyć opcje „Pytaj o datę każdego podpisu” i „Tryb offline”, wybrać katalog raportu,
- śledzić stan i wynik każdego pliku. Podwójne kliknięcie wiersza otwiera raport pliku.

Przy uruchomieniu z Eksploratora na chwilę mignie okno konsoli, zanim program je ukryje.

### Konsola

Uruchomienie z wiersza poleceń (cmd, PowerShell) z argumentami działa w trybie konsolowym:

```
weryfikator-podpisow.exe [-pytaj] [-y] [-offline] [-o katalog_raportu] plik.pdf katalog\ ...
```

| Opcja | Znaczenie |
|---|---|
| `-gui` | otwórz okno programu także przy uruchomieniu z konsoli |
| `-pytaj` | pytaj o datę każdego podpisu (domyślnie przyjmowana jest data wykryta w podpisie) |
| `-y` | nie czekaj na Enter na końcu (do skryptów) |
| `-o` | katalog raportu (domyślnie `weryfikacja-podpisow-<data>` obok pierwszego pliku) |
| `-offline` | bez połączeń sieciowych; wynik będzie nierozstrzygający, bo nie da się wtedy sprawdzić list zaufanych usług |

Gotowy plik `.exe` pobierzesz z [Releases](../../releases). Sprawdź [Code signing policy](#code-signing-policy).

Domyślnie program przyjmuje dla każdego podpisu najsilniejszą wykrytą datę i pokazuje w konsoli wszystkie
daty znalezione w podpisie. Z opcją `-pytaj` czeka na decyzję: Enter przyjmuje proponowaną datę, można też
wpisać inną (`RRRR-MM-DD GG:MM[:SS]`, czas lokalny), np. gdy użytkownik wie, kiedy plik podpisano.
Podpis bez żadnej daty przy domyślnym trybie dostaje wynik nierozstrzygający.

Wynik:
- `index.html` — zestawienie zbiorcze i log zapytań sieciowych,
- `NNN-<plik>.html` — raport dla każdego pliku. Przycisk „Drukuj raport” otwiera okno drukowania przeglądarki;
  stamtąd można wydrukować raport albo zapisać go jako PDF, np. jako załącznik do akt.
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
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=0.1.0" -o weryfikator-podpisow.exe .
```

Wydanie: wypchnięcie tagu `v*` (np. `git tag -a v0.1.1 -m v0.1.1 && git push origin v0.1.1`) uruchamia
[workflow release](.github/workflows/release.yml). Workflow wykonuje testy, buduje `.exe` z metadanymi wersji,
podpisuje go (jeśli podpis jest skonfigurowany), wylicza `SHA256SUMS` i tworzy GitHub Release.

Niepodpisany `.exe` może zostać zatrzymany przez SmartScreen lub AppLocker.

## Podpisywanie wydań — procedura (SignPath Foundation)

Status: **wydania nie są jeszcze podpisywane**. Workflow publikuje je bez podpisu, dopóki nie ustawi się
zmiennej `SIGNPATH_ORGANIZATION_ID`.

Warunki: SignPath Foundation podpisuje wyłącznie projekty open source z publicznym repozytorium, które
mają już opublikowane wydanie ([warunki](https://signpath.org/terms)).

1. Upublicznij repozytorium: Settings → General → Danger Zone → Change visibility → Public.
   Upublicznienie włącza też atestację builda (`attest-build-provenance`), w prywatnych repo dostępną tylko
   w GitHub Enterprise Cloud.
2. Włącz uwierzytelnianie dwuskładnikowe (2FA) na koncie GitHub.
3. Złóż wniosek na [signpath.org](https://signpath.org/) (formularz dla projektów OSS). Podaj:
   - adres repozytorium i istniejącego wydania,
   - link do sekcji [Code signing policy](#code-signing-policy),
   - link do [PRIVACY.md](PRIVACY.md),
   - opis działania programu.
4. Po akceptacji wniosku skonfiguruj SignPath (z włączonym MFA):
   - Trusted Build Systems → dodaj predefiniowany **GitHub.com** i powiąż go z projektem,
   - konfiguracja artefaktu → wklej treść [.signpath/artifact-configuration.xml](.signpath/artifact-configuration.xml),
   - polityka podpisu z ręcznym zatwierdzaniem (zatwierdzający zgodnie z tabelą ról poniżej),
   - token API dla użytkownika z rolą *submitter* w tej polityce,
   - opcjonalnie aplikacja SignPath dla GitHub, potrzebna do oceny audit logu
     ([dokumentacja](https://docs.signpath.io/trusted-build-systems/github)).
5. Skonfiguruj GitHub w zakładce Settings → Secrets and variables → Actions:
   - secret `SIGNPATH_API_TOKEN` (token z kroku 4),
   - zmienne `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG` i `SIGNPATH_SIGNING_POLICY_SLUG`
     (wartości z panelu SignPath).
6. Wypchnij nowy tag wersji. Workflow wyśle `.exe` do SignPath i poczeka do 2 godzin. Zatwierdź żądanie
   w panelu SignPath, a podpisany plik trafi do Release. Wcześniejszych wydań nie da się podpisać wstecz.

Alternatywa przy repozytorium prywatnym: komercyjny certyfikat OV do podpisywania kodu, np. Certum Standard
Code Signing. Wymaga przerobienia kroku podpisu w workflow na API dostawcy.

## Code signing policy

> Planowane: wniosek do SignPath Foundation jeszcze nie został złożony (procedura powyżej). Do tego czasu wydania są niepodpisane.

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
