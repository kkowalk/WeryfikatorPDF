# Polityka prywatności

WeryfikatorPDF działa lokalnie. **Weryfikowane dokumenty ani ich treść nie są nigdzie wysyłane.**

Program nie zbiera telemetrii, nie wysyła statystyk i nie korzysta z usług autora.

## Połączenia sieciowe

Wyłącznie w celu weryfikacji program łączy się z:

| Cel | Adres | Co jest wysyłane |
|---|---|---|
| Unijna lista list zaufanych (LOTL) | `https://ec.europa.eu/tools/lotl/eu-lotl.xml` | standardowe żądanie HTTPS GET |
| Krajowe listy zaufanych usług | adresy HTTPS wskazane w LOTL | standardowe żądanie HTTPS GET |
| Listy unieważnionych certyfikatów (CRL) | adresy zapisane w certyfikatach (CRL Distribution Points) | standardowe żądanie HTTP(S) GET |
| Usługi OCSP | adresy zapisane w certyfikatach (Authority Information Access) | numer seryjny certyfikatu oraz skróty nazwy i klucza wystawcy (RFC 6960) |

Adresy CRL i OCSP są używane tylko dla certyfikatów, których ścieżka certyfikacji prowadzi do usługi z unijnej listy
zaufanych usług. Odbiorcy tych żądań (Komisja Europejska, organy nadzoru, dostawcy usług zaufania) widzą adres IP
komputera i, w przypadku OCSP, którego certyfikatu dotyczy zapytanie.

Wszystkie wykonane zapytania są wymienione w raporcie (`index.html`, sekcja „Zapytania sieciowe”), a pobrane dane
zapisywane są lokalnie w katalogu `dowody/`.

## Wyłączenie

Opcja `-offline` wyłącza wszystkie połączenia sieciowe. Weryfikacja korzysta wtedy wyłącznie z danych osadzonych w pliku PDF.
Bez list zaufanych usług nie da się potwierdzić kotwicy zaufania, więc wynik będzie nierozstrzygający.
