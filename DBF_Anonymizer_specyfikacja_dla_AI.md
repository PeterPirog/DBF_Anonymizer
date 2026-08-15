# DBF_Anonymizer — specyfikacja projektu, instrukcja operacyjna i kontekst dla modelu AI

> Dokument przeznaczony do przekazania modelowi AI pracującemu lokalnie w Warp
> (np. GLM 5.2). Należy przeczytać go w całości przed modyfikacją repozytorium.
> Opisuje stan docelowy, bezwzględne inwarianty, architekturę, historyczne błędy,
> testy akceptacyjne oraz zasady bezpieczeństwa.

## 0. Metryka dokumentu i sposób użycia

- Repozytorium: `https://github.com/PeterPirog/DBF_Anonymizer`
- Gałąź bazowa: `main`
- Stan odniesienia: commit `0687d5251fe3095b7209bace62b8c51948fb296d`
- Wersja pakietu w stanie odniesienia: `0.3.0`
- Data przygotowania dokumentu: 2026-08-15
- Główna platforma produkcyjna: Windows z Visual FoxPro 9.0
- Wspierany Python: 3.10 lub nowszy; CI sprawdza 3.10, 3.12 i 3.14

Ten dokument jest stałym kontekstem projektu. Nie zastępuje odczytania aktualnego
kodu i `git diff`. Jeśli kod na bieżącej gałęzi jest nowszy niż podany commit,
model musi porównać dokument z kodem i zachować nowsze, poprawnie przetestowane
rozwiązania. Nie wolno cofać istniejących zabezpieczeń tylko dlatego, że prostszy
kod wygląda atrakcyjniej.

W tym dokumencie:

- **MUSI / NIE WOLNO** oznacza wymaganie bezwzględne;
- **POWINNO** oznacza wymaganie, od którego można odstąpić wyłącznie po opisaniu
  przyczyny, ryzyka i testu zastępczego;
- **MOŻE** oznacza dopuszczalny wariant implementacyjny.

Polecenie dla modelu powinno brzmieć przykładowo:

```text
Przeczytaj w całości plik DBF_Anonymizer_specyfikacja_dla_AI.md. Następnie
sprawdź aktualny kod, git status, dokumentację i testy. Traktuj wymagania MUSI
oraz NIE WOLNO jako inwarianty. Nie przepisuj działających części bez potrzeby.
Przed zmianą wypisz inwarianty, na które wpływa zadanie. Zaimplementuj zadanie,
dodaj test regresyjny, uruchom compileall i pełny pytest. Nie używaj danych
produkcyjnych w testach i nie scalaj zmian przy nieudanym CI.

Konkretne zadanie: <tu wpisz zadanie>.
```

---

## 1. Cel biznesowy i definicja sukcesu

Źródłowy katalog zawiera zbiór tabel DBF będących relacyjną bazą danych Visual
FoxPro. Tabel nie wolno traktować jako niezależnych plików. Wartości tekstowe
pełnią rolę kluczy, identyfikatorów i pól łączących tabele.

Repozytorium ma realizować trzy podstawowe operacje:

1. **Anonimizacja** całego katalogu DBF do katalogu wynikowego o zachowanej
   strukturze podkatalogów.
2. **Recovery**, czyli jednoznaczne odtworzenie oryginalnych danych na podstawie
   katalogu anonimowego i chronionego słownika.
3. **Self-test**, czyli pełny round-trip:
   `źródło → anonimizacja → recovery → porównanie`, wraz z kontrolą VFP/CDX.

Sukces oznacza jednocześnie:

- ta sama niepusta wartość tekstowa `C` z dowolnej tabeli, pola lub podkatalogu
  otrzymuje to samo mapowanie globalne;
- mapowanie jest bijekcją: jeden oryginał ma dokładnie jeden anonim i jeden anonim
  wskazuje dokładnie jeden oryginał;
- wartość anonimowa nie jest identyczna z oryginałem;
- pseudonim zachowuje dokładną długość bajtową w stronie kodowej DBF;
- dane anonimowe pozostają poprawnymi tabelami VFP;
- recovery przywraca liczbę i kolejność rekordów, wartości, memo, flagi usunięcia
  oraz relacje tekstowe;
- strukturalne CDX są przebudowane przez pełny VFP i dają się używać;
- błąd choć jednej tabeli nie publikuje częściowego katalogu ani częściowego
  słownika;
- proces jest możliwie szybki, wieloprocesowy i ogranicza zużycie pamięci;
- log pozwala ustalić tabelę, etap i typ awarii bez ujawniania treści danych.

Self-test wymaga przede wszystkim **zgodności kanonicznej danych**, a nie
identycznego SHA-256 całego pliku DBF. Nagłówki, znaczniki czasu lub techniczna
organizacja FPT mogą różnić się bajtowo, jeżeli dane i semantyka VFP są takie
same. Tam, gdzie historyczna reprezentacja bajtowa ma znaczenie (`N/F/L` i układ
nagłówka), projekt zachowuje ją osobnymi, kontrolowanymi mechanizmami.

---

## 2. Zakres danych i identyfikacja tabel

### 2.1. Obsługiwane artefakty

- `.dbf` — tabela danych;
- `.fpt` — memo powiązane z DBF, jeśli tabela ma pola `M/G`;
- `.cdx` — strukturalny indeks o tym samym rdzeniu nazwy co DBF.

Wyszukiwanie rozszerzeń oraz dopasowanie DBF↔CDX MUSI być niewrażliwe na
wielkość liter, ponieważ na Windows występują kombinacje `.DBF`, `.dbf`, `.CDX`
i `.cdx`.

Narzędzie nie jest kopierką całego katalogu. Publikuje artefakty DBF/FPT/CDX oraz
manifest. Pliki aplikacji VFP nie są automatycznie kopiowane jako część wyniku.

### 2.2. Tabele techniczne projektów VFP

Pliki DBF skojarzone z artefaktami projektu/formularza/raportu VFP powinny być
pomijane. Obecna lista par obejmuje m.in.:

`SCX/SCT`, `FRX/FRT`, `LBX/LBT`, `MNX/MNT`, `PJX/PJT`, `VCX/VCT`,
`DBC/DCT/DCX` oraz `PRG`.

Jeśli w tym samym katalogu istnieje plik o tym samym rdzeniu i jednym z tych
rozszerzeń, odpowiadający DBF nie jest traktowany jak tabela danych. Zmiana tej
reguły wymaga fixture VFP oraz jednoznacznego uzasadnienia.

`FOXUSER.DBF` jest domyślnie pomijany jako techniczny zasób ustawień środowiska
VFP. Inne wykluczenia są dozwolone tylko jako jawne wzorce operatora. Każde
wykluczenie MUSI trafić do logu i pola `excluded_tables` manifestu. Nie wolno
wykluczać czynnej tabeli aplikacyjnej tylko po to, aby ominąć brak CDX.

### 2.3. Ścieżka względna jest częścią tożsamości pliku

W bazie mogą istnieć pliki o tej samej nazwie, np.:

```text
DANE/klienci.dbf
ARCHIWUM/klienci.dbf
ODDZIAL_2/klienci.dbf
```

Każdy z nich jest osobną tabelą fizyczną i MUSI zachować swoją ścieżkę względem
katalogu źródłowego. Nie wolno używać samej nazwy pliku jako identyfikatora
zadania, memo, raportu, katalogu tymczasowego ani manifestu.

Katalog zadania jest wyliczany z SHA-256 ścieżki względnej. Zapobiega to kolizji
plików o tej samej nazwie i konfliktom równoległych raportów rekonstrukcji.

Globalne mapowanie pól `C` jest natomiast celowo niezależne od ścieżki, nazwy
tabeli i nazwy pola.

---

## 3. Kontrakt transformacji według typu pola

| Typ DBF | Anonimizacja | Recovery | Inwarianty |
|---|---|---|---|
| `C` | globalny pseudonim | odwrócenie przez SQLite | ten sam tekst wszędzie → ten sam anonim; identyczna długość bajtowa; bijekcja |
| `M/G` | domyślnie `MEMO`, opcjonalnie bez zmian | oryginał pozycyjnie ze słownika | liczba i kolejność rekordów muszą być identyczne |
| `D` | przesunięcie o stałą liczbę dni | przesunięcie odwrotne | `NULL` pozostaje `NULL` |
| `T` | przesunięcie części daty, czas pozostaje | przesunięcie odwrotne | zachowanie części czasu |
| `N/F` | logicznie bez zmian | bez zmian | dokładne surowe bajty są przywracane po zapisie |
| `L` | bez zmian | bez zmian | dokładne surowe bajty są przywracane po zapisie |
| nieznany | zachowanie wartości | zachowanie wartości | nie wolno po cichu usuwać pola |

### 3.1. Pola tekstowe `C`

Wymagania bezwzględne:

- kluczem mapowania jest dokładna, niepusta wartość tekstowa;
- `NULL` i pusty ciąg pozostają bez zmian;
- mapa nie zawiera nazwy tabeli ani pola, dlatego relacje między tabelami są
  zachowane;
- `text_map.original` jest kluczem głównym, a `text_map.anonymized` ma indeks
  `UNIQUE`;
- pseudonim ma tę samą długość **bajtową**, nie tylko tę samą liczbę znaków;
- pseudonim musi dać się zakodować w każdej stronie kodowej używanej przez
  wystąpienia danej wartości;
- pseudonim nie może być równy oryginałowi, również gdy domena jest całkowicie
  zajęta; wtedy implementacja wykonuje bezpieczną zamianę w ramach bijekcji;
- kolizje nie mogą być rozwiązywane przez utratę danych ani mapowanie wielu
  oryginałów na ten sam anonim.

Alfabet pseudonimów jest budowany ze wspólnych, drukowalnych, jednobajtowych
znaków stron kodowych wykrytych w schematach. Nietypowe znaki narodowe i
interpunkcja są dozwolone. Wyklucza się:

- znaki kontrolne;
- białe znaki, w szczególności końcową spację mogącą zostać obciętą;
- duplikaty według `casefold`, np. jednoczesne użycie oczywistej pary `A/a`.

Jeżeli ten sam tekst ma różną długość bajtową w dwóch kodowaniach, program MUSI
zakończyć się błędem `INCONSISTENT_TEXT_BYTE_LENGTH`. Nie wolno ratować sytuacji
przez utworzenie osobnego mapowania dla każdej tabeli, ponieważ zerwałoby to
spójność relacyjną.

Jeżeli liczba wartości długości `n` przekracza pojemność `|alfabet|^n`, program
MUSI zakończyć się `TEXT_DOMAIN_CAPACITY`. Nie wolno skracać, wydłużać ani
powielać pseudonimów.

### 3.2. Pola memo `M/G`

Domyślny tryb `memo=mask` zapisuje w anonimie stałą `MEMO`. Oryginały są
przechowywane w SQLite według:

```text
(relative_path, field_name, record_index)
```

Recovery jest pozycyjne, dlatego nie wolno zmieniać kolejności rekordów między
anonimizacją a recovery. Rozbieżność liczby wartości memo i rekordów jest
błędem, nigdy ostrzeżeniem.

Tryb `memo=keep` pozostawia zawartość memo bez zmian. Jest funkcjonalnie
obsługiwany, ale może pozostawić dane osobowe w katalogu anonimowym. Model nie
może prezentować `memo=keep` jako bezpiecznej anonimizacji bez wyraźnego
ostrzeżenia.

### 3.3. Daty i daty-czas

- `--date-offset 0` oznacza brak przesunięcia;
- dodatni lub ujemny offset musi być odwracany dokładnie przez recovery;
- dla `T` przesuwa się data, a nie czas dnia;
- opcja musi być zapisana w metadanych słownika i zgodna przy jego ponownym
  użyciu.

### 3.4. Pola `N/F/L` i surowe rekordy dbfbridge

Pola `N/F/L` są semantycznie identity, ale historyczne DBF mogą zawierać
reprezentacje, których standardowy writer nie potrafi odtworzyć. Przykładem jest
tekst `-32` w polu `N(4,1)`, podczas gdy normalizacja do `-32.0` nie mieści się
w czterech bajtach.

Wymagany algorytm:

1. Podczas transformacji wykryć wartość `N/F`, której writer nie zapisze.
2. Na czas rekonstrukcji użyć bezpiecznego placeholdera, np. `0`.
3. Utworzyć DBF.
4. Przywrócić z `__dbfbridge_raw_record__` wyłącznie zakresy bajtów pól
   `N/F/L`.
5. Sprawdzić liczbę rekordów, długość rekordu, adresy i długości pól.
6. Wymusić `flush` i `fsync`.

Pełny `__dbfbridge_raw_record__` NIE MOŻE zostać przekazany writerowi ani
wpisany w całości do gotowego rekordu, ponieważ cofnąłby anonimizację pól `C`.
Surowe metadane można zachować wyłącznie dla pól nietransformowanych.

---

## 4. Globalny słownik SQLite

### 4.1. Decyzja architektoniczna

Źródłem prawdy jest jeden przenośny plik `dictionary.sqlite3`. Projekt nie używa
Redis i NIE POWINIEN dodawać Redis jako zależności, procesu pomocniczego ani
alternatywnej ścieżki bez odrębnej decyzji architektonicznej i dowodu przewagi.

SQLite wybrano, ponieważ zapewnia:

- trwałość po zakończeniu procesu;
- transakcje;
- indeksy `PRIMARY KEY` i `UNIQUE` pilnujące bijekcji;
- łatwy backup i przenoszenie;
- jednego writera podczas budowy oraz wielu odczytów read-only w workerach;
- brak dodatkowej usługi, portu, konfiguracji i ryzyka pozostawienia danych w
  obcej instancji.

### 4.2. Schemat logiczny wersji 4

```text
metadata(key PRIMARY KEY, value_json)
files(relative_path PRIMARY KEY, table_name)
text_map(original PRIMARY KEY, anonymized UNIQUE, byte_length)
text_sources(original, relative_path, field_name, encoding, byte_length)
memo_values(relative_path, field_name, record_index, value_json)
```

`text_sources` jest potrzebne do diagnozowania kodowań, długości i braku
pojemności bez ujawniania treści wartości w logach.

Nowa anonimizacja tworzy SQLite v4. Recovery zachowuje zgodność z SQLite v3 oraz
starszymi słownikami JSON v1/v2. Usunięcie zgodności wstecznej wymaga migratora,
testów fixture oraz osobnej decyzji wersjonującej.

### 4.3. Determinizm i sól

Sól jest tajnym, stałym wejściem do deterministycznego wyznaczania kandydatów
pseudonimów. To nie jest szyfrowanie i nie zastępuje ochrony słownika.

- Ten sam kompletny zbiór danych, konfiguracja i sól powinny dawać ten sam
  słownik.
- Istniejący słownik gwarantuje stabilność wcześniejszych mapowań przy dodaniu
  nowych wartości.
- Sól jest zapisywana w metadanych tylko jako SHA-256.
- Recovery nie wymaga podania soli, bo korzysta z gotowej mapy odwrotnej.
- Pusta sól jest technicznie dopuszczona dla minimalistycznego CLI, ale NIE JEST
  zalecana dla danych produkcyjnych.
- Przy ponownym użyciu słownika należy podać dokładnie tę samą sól.
- Zmiana soli, `memo_mode`, `date_offset_days`, `text_mode` albo zestawu kodowań
  musi zakończyć się `INCREMENTAL_DICTIONARY_CONFIG_MISMATCH`.

Sól podana bezpośrednio w wierszu poleceń może pozostać w historii PowerShell i
być widoczna na liście procesów. Bezpieczniejszy interfejs pobierający sekret ze
zmiennej/menedżera poświadczeń jest sensownym przyszłym usprawnieniem. Nie należy
jednak zmieniać obecnego CLI bez zachowania kompatybilności.

### 4.4. Konwersja przyrostowa

Domyślnie istniejący słownik jest kopiowany do stagingu i rozszerzany:

- istniejące `original↔anonymized` pozostają bez zmian;
- `files`, `text_sources` i pozycyjne `memo_values` są odświeżane dla bieżącego
  przebiegu;
- nowe wartości otrzymują wolne, deterministyczne pseudonimy;
- oryginalny opublikowany słownik nie jest modyfikowany w miejscu.

`--fresh-dictionary` świadomie buduje mapę od zera. Nie wolno włączać tej opcji
automatycznie jako sposobu na obejście konfliktu konfiguracji.

### 4.5. Wydajność SQLite

- zapis wykonuje jeden koordynator, nie równoległe procesy piszące;
- dodawanie i odczyty są wsadowe;
- bieżące wartości są przetwarzane strumieniowo z JSONL;
- procesy transformujące otwierają bazę w `mode=ro` i `query_only`;
- zapisy mapowań są grupowane (obecnie do 10 000), a zapytania `IN` mieszczą się
  poniżej limitu parametrów SQLite (obecnie 900);
- ustawienia cache/mmap nie mogą prowadzić do nieograniczonego wzrostu RAM.

---

## 5. Pipeline anonimizacji

Kolejność etapów jest częścią kontraktu bezpieczeństwa:

1. Walidacja źródła, opcji, katalogów, liczby workerów i wielkości partii.
2. Rekurencyjne znalezienie wszystkich DBF danych.
3. Preflight CDX: odczyt flagi strukturalnego indeksu z nagłówka DBF i
   natychmiastowy `SOURCE_CDX_MISSING`, jeżeli brak CDX o tym samym rdzeniu.
4. Równoległy eksport każdego DBF przez dbfbridge do izolowanego
   `JSONL + _schema.json`, z memo inline i rekordami deleted.
5. Jeśli eksport choć jednej tabeli się nie uda — `INCOMPLETE_EXPORT`, brak
   budowy słownika i brak publikacji.
6. Budowa jednego globalnego słownika SQLite na podstawie kompletnego obrazu
   bazy.
7. Równoległa, strumieniowa transformacja JSONL w partiach.
8. Rekonstrukcja DBF/FPT w osobnym katalogu każdego zadania.
9. Kontrolowana normalizacja nagłówka VFP i przywrócenie surowych `N/F/L`.
10. Ponowna walidacja kanoniczna, jeśli dbfbridge zgłosił wyłącznie różnicę,
   którą może naprawić łatka identity.
11. Kopiowanie definicji CDX i obowiązkowy `REINDEX` w pełnym VFP.
12. Utworzenie manifestu integralności DBF/FPT/CDX i wykluczeń.
13. Jednoczesna publikacja kompletnego katalogu wyniku oraz słownika.

Nie wolno budować słownika na części tabel po niepełnym eksporcie. Taki słownik
nie reprezentowałby całej bazy i mógłby inaczej przydzielić pseudonimy.

### 5.1. Staging i publikacja transakcyjna

Wynik i słownik są budowane w katalogach typu:

```text
.<nazwa>.build-<pid-token>
```

Przy publikacji istniejące cele są najpierw przenoszone do katalogów backup,
a następnie staging jest atomowo podstawiany. Jeżeli drugi lub kolejny krok
publikacji nie powiedzie się, poprzednie katalogi są przywracane.

Wymagania:

- status `FAILED` w dowolnej tabeli blokuje publikację całości;
- poprzedni poprawny wynik i słownik mają pozostać nienaruszone;
- `--no-overwrite` nie może usunąć ani częściowo podmienić istniejącego celu;
- przerwanie procesu nie może publikować stagingu;
- pliki tymczasowe i backupy należy usuwać po sukcesie;
- manifest powstaje przed publikacją.

Operator MUSI umieszczać wynik i słownik poza katalogiem źródłowym. Obecna
walidacja kodu nie odrzuca wszystkich możliwych przypadków zagnieżdżenia celu
wewnątrz źródła; pełna kontrola nakładających się ścieżek jest wskazanym
usprawnieniem P0.

### 5.2. Kody wyjścia

- `0` — pełny sukces bez ostrzeżeń;
- `1` — błąd, wynik nie został opublikowany;
- `2` — zakończenie z ostrzeżeniami; wynik może być opublikowany i wymaga
  kontroli komunikatów;
- `130` — przerwanie przez użytkownika (`Ctrl+C`).

Nie wolno traktować samego istnienia katalogu wynikowego jako dowodu sukcesu.
Należy sprawdzić `$LASTEXITCODE`, końcowy wpis logu i manifest.

---

## 6. Multiprocessing, strumieniowanie i wykorzystanie CPU

### 6.1. Semantyka `--workers`

- `--workers 0` — wartość domyślna; automatycznie używa do `os.cpu_count()`, ale
  nigdy więcej procesów niż liczba zadań;
- `--workers 1` — wykonanie sekwencyjne, przydatne do diagnostyki;
- `--workers N` — maksymalnie `N` procesów.

Równolegle wykonywane są kosztowne etapy per tabela: eksport,
anonimizacja/rekonstrukcja oraz recovery. Budowa globalnego słownika ma jednego
writera, a workery korzystają z odczytu SQLite read-only.

Każdy worker MUSI mieć osobny katalog zadania. Nie wolno współdzielić jednego
`reconstruction_report.jsonl` między procesami. To zapobiega m.in. Windows
`WinError 32` oraz mieszaniu wyników tabel o tej samej nazwie.

### 6.2. Ograniczenie pamięci

- JSONL jest czytany iteratorami;
- domyślna partia wynosi 5000 rekordów;
- lookupy SQLite są wsadowe;
- porównanie self-testu używa `zip_longest` dwóch strumieni;
- nie wolno wracać do `list(all_records)` w głównej ścieżce SQLite dla dużych
  tabel;
- ścieżka zgodności ze starym JSON może być mniej wydajna, ale nie powinna
  wpływać na główną ścieżkę v4.

### 6.3. Niskie użycie CPU nie dowodzi braku multiprocessing

Eksport DBF, zapis JSONL, rekonstrukcja, SQLite oraz dysk mogą być ograniczone
I/O. Przy małej liczbie wielkich tabel maksymalna równoległość jest dodatkowo
ograniczona liczbą tabel. Obciążenie 5% może być poprawne.

Diagnostyka multiprocessing powinna sprawdzić:

- log `phase=... event=start ... workers=N`;
- różne PID w logu;
- liczbę równoległych procesów Pythona;
- przepustowość i opóźnienie dysku;
- czasy etapów osobno, a nie tylko średnie CPU.

W kodzie używającym API na Windows wywołanie musi znajdować się pod:

```python
if __name__ == "__main__":
    ...
```

---

## 7. Visual FoxPro i CDX — wymaganie bezwzględne

CDX zawiera wyrażenia i fizyczne klucze indeksu. Po zmianie wartości pól samo
skopiowanie oryginalnego CDX daje nieaktualny lub niebezpieczny indeks.

Wymagany algorytm dla każdej tabeli ze strukturalnym CDX:

1. Znaleźć CDX o tym samym rdzeniu, niewrażliwie na wielkość liter.
2. Skopiować go wyłącznie jako nośnik definicji tagów.
3. Otworzyć docelowy DBF w pełnym Visual FoxPro przez COM
   `VisualFoxPro.Application`.
4. Otworzyć tabelę `EXCLUSIVE`.
5. Sprawdzić, czy przed przebudową istnieją definicje tagów.
6. Wykonać obowiązkowy `REINDEX`.
7. Sprawdzić liczbę i nazwy tagów.
8. Ustawić każdy tag jako porządek i wykonać `GO TOP`.
9. Zamknąć tabelę i zwolnić obiekt COM również po błędzie.

Jeśli źródłowy DBF ma flagę indeksu strukturalnego, ale nie ma odpowiadającego
CDX, operacja MUSI zakończyć się `SOURCE_CDX_MISSING` przed eksportem i budową
słownika.

Jeżeli Windows, COM VFP, definicje tagów, `REINDEX` lub weryfikacja zawiodą,
operacja MUSI zakończyć się `CDX_REINDEX_FAILED` i zablokować publikację.
Nie wolno pozostawiać skopiowanego, nieprzebudowanego CDX.

Sam runtime VFP, ODBC, biblioteka `dbf` ani parser CDX nie zastępują pełnego
Visual FoxPro dla tej operacji.

---

## 8. Historyczne problemy i obowiązkowe regresje

Poniższe przypadki wystąpiły na rzeczywistym katalogu CWOM-B. Nie wolno ich
usuwać z testów ani upraszczać bez odpowiednika.

### 8.1. `pers_nob_arch.DBF` i `N(4,1)`

dbfbridge zapisuje w schemacie:

- `decimal_count`, nie tylko historyczne `decimal`;
- `declared_or_detected_encoding`, nie tylko historyczne `codepage`.

Loader schematu MUSI obsługiwać bieżące klucze oraz bezpieczne fallbacki dla
starszych schematów. Błędne odczytanie `N(4,1)` jako `N(4,0)` spowodowało:

```text
Numeric value Decimal('-32') does not fit N/F(4,1)
```

Test musi potwierdzać, że `-32` jest zastępowane placeholderem, a następnie
przywracane z surowych bajtów.

### 8.2. `mps_normy.dbf` i nagłówek 545/808

Writer VFP używany przez dbfbridge może dodać opcjonalny 263-bajtowy obszar
backlink. Niektóre prawidłowe źródła go nie mają. Dla 16 pól kompaktowa długość
wynosi:

```text
32 + 16 * 32 + 1 = 545
```

Writer utworzył 808 bajtów, czyli `545 + 263`, co dało:

```text
Header length mismatch: reconstructed 808, schema 545
```

Dozwolona naprawa jest bardzo wąska:

- tymczasowo dopuścić 263 bajty tylko wtedy, gdy źródłowy nagłówek jest dokładnie
  kompaktowy `32 + liczba_pól*32 + 1`;
- po rekonstrukcji przywrócić oryginalny nagłówek z `header_base64`;
- zachować wygenerowaną liczbę rekordów i zweryfikować długość rekordu;
- atomowo usunąć dokładnie 263 nadmiarowe bajty;
- dla każdego innego układu zakończyć się `HEADER_LAYOUT_*`.

Nie wolno ogólnie „przycinać” 263 bajtów każdego DBF.

### 8.3. `indexy_4.DBF` i różnice kanoniczne `P_PWAZ_K/P_PWAZ_U`

dbfbridge może zwrócić status `FAILED` z samym błędem kanonicznym, zanim kod
przywróci historyczne bajty `N/F/L`. W takim przypadku wolno podjąć naprawę
wyłącznie według procedury:

1. Potwierdzić, że wszystkie błędy wyniku są tylko błędem typu
   `Canonical checksum mismatch`.
2. Przywrócić układ nagłówka.
3. Przywrócić surowe pola `N/F/L`.
4. Ponownie policzyć kanoniczny SHA-256 oczekiwanego JSONL oraz gotowego DBF.
5. Tylko przy pełnej równości wyczyścić błąd i oznaczyć wynik ostrzeżeniem
   `CANONICAL_MISMATCH_REPAIRED_BY_RAW_IDENTITY_PATCH`.
6. Jeśli sumy nadal się różnią — pozostawić `FAILED` i nie publikować.

Nie wolno ignorować błędu kanonicznego, porównywać tylko liczby rekordów ani
zamieniać go na ostrzeżenie bez ponownego hasha.

### 8.4. Duplikaty nazw i Windows sharing violation

Każda tabela ma izolowany katalog eksportu i rekonstrukcji oparty na ścieżce
względnej. Test musi obejmować co najmniej dwa DBF o tej samej nazwie w różnych
podkatalogach oraz wykonanie wieloprocesowe.

### 8.5. Polskie znaki w terminalu

CLI rekonfiguruje stdout/stderr do UTF-8 z `backslashreplace`, a plik logu jest
UTF-8. W PowerShell przed pracą zaleca się:

```powershell
chcp 65001 > $null
$env:PYTHONUTF8 = "1"
```

Dziwne znaki w konsoli mogą wynikać z kodowania hosta lub fontu i nie muszą
oznaczać uszkodzenia DBF. Decydujące są schemat kodowania, plik logu UTF-8 i
self-test.

---

## 9. Instalacja i polecenia PowerShell na Windows

### 9.1. Instalacja środowiska

```powershell
Set-Location "D:\Warp_directory\DBF_Anonymizer"

py -3.12 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

chcp 65001 > $null
$env:PYTHONUTF8 = "1"
```

Zależność `dbfbridge` jest przypięta w `pyproject.toml` do konkretnego commita.
Nie wolno aktualizować tego SHA przy okazji innej zmiany. Aktualizacja wymaga
osobnego PR, przeglądu zmian formatu `_schema.json`, pełnego pytest i testu na
rzeczywistych fixture VFP.

### 9.2. Sprawdzenie COM Visual FoxPro

```powershell
$vfp = New-Object -ComObject VisualFoxPro.Application
$vfp.Version
$vfp.Quit()
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($vfp) | Out-Null
```

### 9.3. Minimalna anonimizacja

Minimalny publiczny kontrakt CLI ma pozostać prosty:

```text
dbf-anonymizer anonymize [<dir>] [--out OUT] [--dict-dir DICT]
```

Operator może skopiować śledzony `.env.example` do ignorowanego `.env` i wpisać
tam źródło, wynik, słownik, log, sól, workerów oraz konfigurację VFP. Wartości
środowiska PowerShell mają pierwszeństwo przed plikiem, a argumenty CLI przed
wartościami domyślnymi. `.env` NIE MOŻE trafić do Git.

```powershell
Copy-Item .env.example .env
notepad .env
dbf-anonymizer anonymize
```

`DBF_ANON_VFP_EXE` może wskazywać pełną ścieżkę `vfp9.exe` do wczesnej
walidacji instalacji. Kontrolowane otwarcie i `REINDEX` nadal MUSZĄ używać COM z
`DBF_ANON_VFP_PROGID`.

Przykład z samym źródłem:

```powershell
dbf-anonymizer anonymize "D:\DANE_WOM\CWOM-B"
```

Domyślnie powstaną:

```text
D:\DANE_WOM\CWOM-B_anonymized
D:\DANE_WOM\CWOM-B_dict
```

Przykład z własnym wynikiem:

```powershell
dbf-anonymizer anonymize "D:\DANE_WOM\CWOM-B" `
  --out "D:\Warp_directory\CWOM-B_anonymized"
```

Bez `--dict-dir` słownik powstanie równolegle do faktycznego `--out`:

```text
D:\Warp_directory\CWOM-B_dict
```

### 9.4. Zalecana anonimizacja produkcyjna z logiem

```powershell
$env:DBF_ANON_SALT = "TU-WPROWADZ-DLUGA-STALA-TAJNA-SOL"

python -m dbf_anonymizer anonymize "D:\DANE_WOM\CWOM-B" `
  --out "D:\Warp_directory\CWOM-B_anonymized" `
  --dict-dir "D:\Warp_directory\CWOM-B_dictionary" `
  --salt $env:DBF_ANON_SALT `
  --workers 0 `
  --batch-size 5000 `
  --log-level INFO `
  --log-file "D:\Warp_directory\CWOM-B_conversion.log"

$LASTEXITCODE
```

### 9.5. Recovery

```powershell
python -m dbf_anonymizer recover `
  "D:\Warp_directory\CWOM-B_anonymized" `
  "D:\Warp_directory\CWOM-B_dictionary" `
  --out "D:\Warp_directory\CWOM-B_recovered" `
  --workers 0 `
  --batch-size 5000 `
  --log-file "D:\Warp_directory\CWOM-B_recover.log"

$LASTEXITCODE
```

---

## 10. Self-test — procedura i interpretacja

### 10.1. Co wykonuje self-test

Self-test nie jest tylko testem jednostkowym. Wykonuje na źródle:

1. świeżą anonimizację w katalogu tymczasowym (`reuse_dictionary=False`);
2. recovery z utworzonego słownika;
3. strumieniowy eksport źródła i recovery;
4. porównanie liczby rekordów;
5. porównanie kolejności rekordów;
6. porównanie wszystkich pól danych;
7. porównanie flag `__deleted__`;
8. dla tabel z CDX — otwarcie źródła, anonimu i recovery w VFP;
9. porównanie liczby rekordów oraz zbioru nazw tagów;
10. próbę użycia każdego tagu jako porządku i `GO TOP`.

Robocze pliki powstają pod:

```text
<rodzic źródła>\var\<nazwa źródła>_selftest_<PID>
```

Bez `--keep-temp` są usuwane po zakończeniu.

### 10.2. Zalecane polecenie

Self-test należy wykonywać z takimi samymi opcjami anonimizacji jak przebieg
produkcyjny:

```powershell
$env:DBF_ANON_SALT = "TU-WPROWADZ-TA-SAMA-SOL"

python -m dbf_anonymizer self-test "D:\DANE_WOM\CWOM-B" `
  --memo mask `
  --date-offset 0 `
  --salt $env:DBF_ANON_SALT `
  --workers 0 `
  --batch-size 5000 `
  --log-level INFO `
  --log-file "D:\Warp_directory\CWOM-B_self-test.log"

$LASTEXITCODE
```

### 10.3. Warunki PASS

Poprawny wynik kończy się tekstem:

```text
WYNIK: PASS — wszystkie tabele round-trip kanonicznie identyczne.
```

oraz kodem `0`. Dodatkowo dla źródła z CDX log ma zawierać udane etapy
`phase=cdx event=reindex_done`. Jeśli test VFP nie został rzeczywiście wykonany,
nie wolno twierdzić, że zgodność CDX została potwierdzona.

### 10.4. Diagnostyka z `--keep-temp`

Opcji używać wyłącznie tymczasowo:

```powershell
python -m dbf_anonymizer self-test "D:\DANE_WOM\CWOM-B" `
  --salt $env:DBF_ANON_SALT `
  --workers 1 `
  --keep-temp `
  --log-level DEBUG `
  --log-file "D:\Warp_directory\CWOM-B_self-test-debug.log"
```

`--workers 1` ułatwia przypisanie traceback do jednej tabeli. Katalog `var`
zawiera JSONL oraz słownik z danymi wrażliwymi i po diagnozie MUSI zostać
bezpiecznie usunięty.

### 10.5. Ograniczenie aktualnego self-testu

Aktualny kod w przypadku końcowej niezgodności kanonicznej może dołączyć do
`TableOutcome.errors` reprezentacje `expected` i `actual`. Są one drukowane na
stdout przez raport CLI, więc mogą ujawnić wartości w terminalu, zapisie sesji
Warp albo pliku utworzonym przez przekierowanie wyjścia. Standardowy
`--log-file` nie przechwytuje stdout, lecz nie usuwa to ryzyka. Jest to luka
względem docelowej zasady diagnostyki bez danych osobowych.

Wskazana poprawka P0:

- zastąpić wartości typem, długością i skrótem SHA-256;
- zachować numer rekordu, pole, ścieżkę i kod błędu;
- dodać test, że znana wartość wrażliwa nie występuje w komunikacie;
- do czasu poprawki nie udostępniać pełnych logów self-testu osobom
  nieupoważnionym.

---

## 11. Logowanie i diagnostyka

### 11.1. Format

Log jest kodowany w UTF-8 i powinien zawierać:

```text
timestamp level pid logger phase=<etap> event=<zdarzenie> ...
```

Każdy istotny błąd powinien mieć stabilny kod `[UPPER_SNAKE_CASE]`, ścieżkę
względną tabeli, fazę, typ wyjątku oraz indeks błędu. Nieoczekiwane wyjątki mają
zapisywać traceback.

Gdy worker zwróci status `FAILED` zamiast rzucić wyjątek, koordynator MUSI
zapisać `event=file_failed` osobno dla każdej przyczyny. Przy blokadzie
publikacji log MUSI zawierać:

```text
phase=pipeline event=publication_blocked operation=... failed=...
failed_paths=...
```

Końcowy wpis CLI musi zawierać `event=done` i `exit_code`. Przerwanie ma kod
`event=interrupted` i wyjście 130.

### 11.2. Zasada minimalizacji danych

Log NIE MOŻE zawierać:

- pełnych oryginalnych wartości pól;
- pełnych pseudonimów, jeśli pozwalają łatwo korelować dane;
- zawartości memo;
- surowych rekordów base64;
- zapytań SQL z wartościami danych;
- zawartości słownika.

Do diagnozy wartości używać:

- numeru rekordu;
- nazwy pola;
- typu;
- długości;
- kodowania;
- skrótu SHA-256;
- liczności i źródeł w formie `ścieżka:pole:kodowanie:liczba`.

Ścieżki, nazwy tabel i traceback również mogą być informacją wewnętrzną, więc
logów nie należy publikować razem z kodem.

### 11.3. Najważniejsze kody

| Kod | Znaczenie / wymagane zachowanie |
|---|---|
| `INCOMPLETE_EXPORT` | eksport nie objął wszystkich tabel; nie budować słownika |
| `TEXT_ENCODING_ERROR` | wartość niedostępna w kodowaniu; podać hash i kontekst |
| `INCONSISTENT_TEXT_BYTE_LENGTH` | ten sam tekst ma różne długości bajtowe; przerwać |
| `TEXT_DOMAIN_CAPACITY` | za mała domena pseudonimów; przerwać |
| `TEXT_DOMAIN_EXHAUSTED` | nie znaleziono wolnego pseudonimu; przerwać |
| `TEXT_DERANGEMENT_FAILED` | nie udało się usunąć punktu stałego; przerwać |
| `GLOBAL_MAPPING_MISSING` | wartość nie istnieje w słowniku; nie ujawniać wartości |
| `INCREMENTAL_DICTIONARY_CONFIG_MISMATCH` | niezgodna konfiguracja starego słownika |
| `RAW_PATCH_*` | niespójne surowe N/F/L; przerwać |
| `HEADER_LAYOUT_*` | niebezpieczny/nieznany układ nagłówka; przerwać |
| `CANONICAL_MISMATCH` | recovery różni się od źródła; FAIL |
| `CANONICAL_MISMATCH_REPAIRED_BY_RAW_IDENTITY_PATCH` | naprawa potwierdzona ponownym hashem; warning |
| `SOURCE_CDX_MISSING` | flaga strukturalna bez CDX; przerwać |
| `CDX_REINDEX_FAILED` | REINDEX/weryfikacja VFP zawiodła; przerwać |
| `VFP_WINDOWS_REQUIRED` | operacja CDX uruchomiona poza Windows |
| `VFP_AUTOMATION_FAILED` | PowerShell/COM VFP zwrócił błąd |
| `VFP_CDX_EMPTY` | brak tagów po REINDEX |
| `VFP_TAG_MISMATCH` | tagi źródła/anonimu/recovery nie są zgodne |

---

## 12. Bezpieczeństwo danych i repozytorium

### 12.1. Słownik jest danymi wrażliwymi

`dictionary.sqlite3` zawiera pełne oryginały pól `C` oraz, przy `memo=mask`,
oryginalne memo. Umożliwia pełne odwrócenie anonimizacji. Nie jest częścią
bezpiecznego wyniku anonimowego.

MUSI obowiązywać:

- nie commitować `dictionary.sqlite3`, `-wal`, `-shm`, `-journal` ani starszych
  `dictionary_*.json/jsonl`;
- przechowywać słownik poza katalogiem synchronizowanym z GitHubem;
- ustawić ACL wyłącznie dla operatorów recovery;
- szyfrować dysk i backup, np. BitLocker;
- przesyłać tylko zaszyfrowane archiwum, hasło innym kanałem;
- przed usunięciem słownika wykonać i zachować wynik self-testu;
- pamiętać, że bez słownika recovery pól `C` i zamaskowanych memo jest
  niemożliwe.

Kod wykonuje best-effort `chmod(0600)`, lecz na Windows nie zastępuje to ACL.

### 12.2. `.gitignore` — pozycje obowiązkowe

Repozytorium musi ignorować co najmniej:

```gitignore
dictionary_*.json
dictionary_*.jsonl
*_dictionary.json
dictionary.sqlite3
dictionary.sqlite3-*
*.sqlite3-journal
*.sqlite3-wal
*.sqlite3-shm
dictionaries/
*_anonymized/
*_recovered/
var/
tmp/
jsonl_source/
jsonl_anonymized/
jsonl_recovered/
*.dbf
*.fpt
*.cdx
selftest_report.json
*_quality_report.jsonl
*.log
```

Przed każdym commitem wykonać:

```powershell
git status --short
git diff --cached --name-only
```

Jeśli pojawi się DBF/FPT/CDX, SQLite, JSONL, log lub katalog danych, commit należy
zatrzymać i usunąć plik ze stagingu. Nie wolno używać prawdziwych danych jako
fixture testowego.

### 12.3. Oryginalne dane

- anonimizacja i self-test nie mogą modyfikować źródła;
- przed produkcyjnym przebiegiem wykonać backup źródła;
- zamknąć tabele w VFP i innych programach, szczególnie przed REINDEX;
- debug artifacts traktować jak oryginalne dane;
- nie wysyłać modelowi AI plików DBF ani słownika, jeśli środowisko nie ma
  odpowiednich gwarancji prywatności.

---

## 13. Manifest integralności

Każdy opublikowany katalog zawiera `dbf_anonymizer_manifest.json` z:

- wersją formatu manifestu;
- operacją `anonymize` albo `recover`;
- ścieżką źródła;
- SHA-256 słownika, jeśli dotyczy;
- listą tabel, liczbą rekordów i statusem;
- listą DBF/FPT/CDX, rozmiarem i SHA-256.

Manifest nie zastępuje self-testu, ale pozwala wykryć późniejszą zmianę lub brak
artefaktu. Modyfikacja po publikacji powoduje niespójność manifestu i powinna być
traktowana jako naruszenie integralności.

W obecnym formacie pole `source` zawiera absolutną ścieżkę lokalną. Przed
przekazaniem katalogu anonimowego poza organizację trzeba traktować manifest jak
metadane wewnętrzne. Docelowo należy rozważyć zapis logicznej nazwy/basename albo
kontrolowaną redakcję ścieżki, bez osłabienia integralności artefaktów.

---

## 14. Architektura modułów i granice odpowiedzialności

```text
src/dbf_anonymizer/
  __init__.py      publiczne API i wersja
  __main__.py      python -m dbf_anonymizer
  cli.py           argparse, UTF-8, logowanie, kody wyjścia
  pipeline.py      orkiestracja, multiprocessing, staging, CDX, self-test
  worker_tasks.py  izolowane zadania eksportu/rekonstrukcji
  atomicfs.py      transakcyjna publikacja wielu katalogów i rollback
  jsonstream.py    iteratory, partie i atomowy zapis JSONL
  tableio.py       skan do SQLite, streaming anonymize/recover
  global_store.py  SQLite v4, globalna bijekcja i lookupy wsadowe
  anonymizer.py    transformacje i recovery rekordów
  transforms.py    transformacje typów podstawowych
  schema.py        zgodny wstecznie odczyt schematu dbfbridge
  rawpatch.py      placeholder i dokładne bajty N/F/L
  layout.py        bezpieczna obsługa opcjonalnego backlinku VFP
  vfp.py           COM VFP, definicje CDX, REINDEX, weryfikacja tagów
  verification.py streaming canonical compare oraz VFP round-trip
  manifest.py      SHA-256 opublikowanych artefaktów
  dictionary.py    zgodność ze starszym JSON v1/v2
  uniqueness.py    legacy mapowanie/unikalność kolumn
```

`pipeline.py` powinien pozostać koordynatorem, a nie miejscem implementacji
każdego szczegółu. Nowe, spójne funkcje dotyczące formatu, bezpieczeństwa lub
weryfikacji należy umieszczać w małych modułach i testować bez uruchamiania całej
bazy.

Model NIE POWINIEN:

- ponownie łączyć `layout.py`, `rawpatch.py`, `vfp.py` i `verification.py` w jeden
  ogromny `pipeline.py`;
- wprowadzać globalnego stanu procesu utrudniającego multiprocessing;
- tworzyć jednego wspólnego katalogu raportów workerów;
- omijać publiczne API bez testu kompatybilności;
- aktualizować jednocześnie dbfbridge i logikę rekonstrukcji bez rozdzielenia
  przyczyn.

Obecna naprawa kanoniczna importuje wewnętrzne elementy
`dbf_bridge.importer.checksum` i `dbf_bridge.importer.reconstruct`. Jest to
kontrolowane przy przypiętej wersji dbfbridge, ale stanowi ryzyko przy aktualizacji
zależności. Test kompatybilności musi wykryć zmianę tych API.

---

## 15. Testy deweloperskie

### 15.1. Minimalny zestaw przed commitem

```powershell
python -m compileall -q src tests
python -m pytest -ra
```

Stan odniesienia po PR #7:

```text
70 passed, 1 skipped
```

Pominięcie dotyczy prawdziwego testu VFP, gdy środowisko nie ma fixture i COM.
Liczba testów może rosnąć; nie należy wymuszać dokładnie 70, lecz nie wolno
tracić istniejących przypadków.

### 15.2. Zakres testów

- `test_transforms.py` — długość, determinizm, memo, daty, identity;
- `test_uniqueness.py` — unikalność i polskie znaki;
- `test_global_store.py` — globalna bijekcja, pojemność, nietypowy alfabet,
  stabilność przyrostowa, brak danych w błędach;
- `test_pipeline.py` — pełny round-trip, wiele tabel, te same nazwy w różnych
  katalogach, multiprocessing i relacje między tabelami;
- `test_atomicfs.py` — pełna publikacja, rollback i `--no-overwrite`;
- `test_rawpatch.py` — `N(4,1)`, `-32`, surowe bajty;
- `test_layout.py` — nagłówek 545/808 i 263-bajtowy backlink;
- `test_schema.py` — `decimal_count` i `declared_or_detected_encoding`;
- `test_worker_tasks.py` — ponowny hash po łatce kanonicznej;
- `test_vfp.py` — dopasowanie CDX, kopiowanie definicji i prawdziwy fixture VFP;
- `test_cli.py` — minimalistyczne CLI, domyślne opcje i końcowy kod logu.

### 15.3. GitHub Actions

Każdy push do `main` i każdy PR uruchamia pełny pytest na:

- Windows + Python 3.10;
- Windows + Python 3.12;
- Windows + Python 3.14.

Prawdziwa integracja VFP działa na self-hosted runnerze z etykietami
`Windows, vfp9`, jeżeli ustawiono:

```text
VFP_SELF_HOSTED=true
VFP_FIXTURE_PATH=<lokalny katalog fixture DBF/FPT/CDX>
```

Publiczne zielone CI nie jest wystarczającym dowodem CDX, jeśli job VFP ma
status `skipped`. Przed wydaniem produkcyjnym dotyczącym CDX MUSI przejść test na
maszynie z prawdziwym VFP.

### 15.4. Reguła dla każdej poprawki błędu

Każdy naprawiony błąd musi otrzymać test, który:

1. odtwarza minimalny rzeczywisty format danych lub schematu;
2. kończy się błędem przed poprawką;
3. przechodzi po poprawce;
4. sprawdza nie tylko brak wyjątku, ale właściwy inwariant;
5. nie zawiera danych produkcyjnych.

---

## 16. Benchmarki i kryteria wydajności

Mikrobenchmark SQLite:

```powershell
python benchmarks\benchmark_sqlite.py --values 1000000 --batch-size 10000
```

Pełny pipeline należy mierzyć osobno:

```powershell
Measure-Command {
  dbf-anonymizer anonymize "D:\DANE_WOM\CWOM-B" `
    --out "D:\Warp_directory\CWOM-B_anonymized" `
    --dict-dir "D:\Warp_directory\CWOM-B_dictionary" `
    --salt $env:DBF_ANON_SALT --workers 0
}
```

Porównanie wydajności jest ważne tylko przy tej samej wersji kodu bazowego,
danych, słowniku, soli, CPU, dysku i wielkości partii. Należy zapisać:

- wersję Pythona i commit;
- CPU i liczbę workerów;
- rodzaj dysku;
- rozmiar danych i liczbę tabel;
- czas eksportu, słownika, rekonstrukcji, CDX i self-testu;
- szczyt pamięci;
- rozmiar SQLite;
- statusy i kod wyjścia.

Nie wolno poprawiać benchmarku przez:

- wyłączenie hasha lub self-testu;
- publikację częściowych tabel;
- pozostawienie starego CDX;
- wczytanie całej bazy do RAM bez limitu;
- osłabienie `synchronous`, transakcji lub `fsync` bez testu awarii;
- usunięcie diagnostyki wymaganej do wykrycia błędu.

---

## 17. Zasady pracy modelu AI nad repozytorium

### 17.1. Przed zmianą

Model MUSI:

1. wykonać `git status --short`;
2. ustalić bazową gałąź i commit;
3. przeczytać pliki związane z zadaniem oraz odpowiadające im testy;
4. wskazać inwarianty z tego dokumentu, na które wpływa zmiana;
5. oddzielić przyczynę błędu od objawu;
6. nie modyfikować ani nie usuwać cudzych, niezwiązanych zmian;
7. nie uruchamiać eksperymentów zapisujących do produkcyjnego źródła.

### 17.2. Podczas implementacji

- zachować minimalistyczny kontrakt CLI;
- zachować zgodność starszych słowników, chyba że zadanie jawnie obejmuje
  migrację;
- używać ścieżek względnych jako tożsamości plików;
- nie logować danych osobowych;
- zachować atomowy zapis plików i katalogów;
- sprawdzać zwracane statusy bibliotek, nie tylko wyjątki;
- nie zmieniać `FAILED` na `WARNING` bez niezależnego dowodu poprawności;
- przy zmianie multiprocessing testować Windows spawn i duplikaty nazw;
- przy zmianie kodowania testować co najmniej cp1250 i dodatkową stronę, np.
  cp852;
- przy zmianie DBF uwzględnić rekordy deleted, FPT, CDX i historyczne wartości
  numeryczne;
- nie dodawać Redis;
- nie dodawać prawdziwego DBF, słownika ani logu do repozytorium.

### 17.3. Po implementacji

Model MUSI:

1. uruchomić `compileall` i pełny `pytest`;
2. podać dokładny wynik testów oraz listę pominiętych;
3. przejrzeć `git diff --check` i `git diff --stat`;
4. sprawdzić `git status --short` pod kątem danych wrażliwych;
5. opisać, które inwarianty potwierdzają nowe testy;
6. jasno wskazać, czego nie dało się przetestować, zwłaszcza VFP COM;
7. nie scalać do `main`, jeśli testy nie przeszły lub PR jest nieaktualny;
8. przed merge ponownie sprawdzić SHA głowy, konflikt z `main` i Windows CI.

### 17.4. Czego modelowi nie wolno robić

- wyłączać błędów dbfbridge tylko po to, aby konwersja „doszła do końca”;
- kopiować CDX i uznawać go za gotowy bez VFP `REINDEX`;
- tworzyć osobnego mapowania tekstu per tabela/pole;
- zastępować SQLite słownikiem w RAM albo Redis bez zachowania trwałej bijekcji;
- zapisywać słownika do katalogu anonimowego;
- używać pełnego raw record do rekonstrukcji anonimowego DBF;
- akceptować różnicy kanonicznej bez ponownego porównania;
- publikować 93 z 94 tabel;
- usuwać testów historycznych jako sposobu na zielone CI;
- przedstawiać skipped VFP test jako sukces integracji VFP;
- commitować artefaktów danych lub sekretów;
- wykonywać destrukcyjnych poleceń na katalogu źródłowym.

---

## 18. Znane ryzyka i zalecane dalsze poprawki

### P0 — bezpieczeństwo i poprawność

1. **Redakcja różnic self-testu:** nie wypisywać surowych `expected/actual`;
   logować typ, długość i hash.
2. **Walidacja nakładania ścieżek:** odrzucać wynik, słownik i temp będące
   źródłem, przodkiem lub potomkiem źródła oraz wzajemnie się zawierające.
3. **Realny VFP CI przed wydaniem CDX:** zapewnić okresowe uruchamianie runnera
   self-hosted, nie polegać wyłącznie na jobie skipped.

### P1 — odporność i utrzymanie

1. Dodać test kompatybilności prywatnych importów checksum dbfbridge przed
   aktualizacją przypiętego commita.
2. Dodać bezpieczniejsze źródło soli, np. jawnie wybraną zmienną środowiskową
   lub plik sekretu, zachowując `--salt` dla kompatybilności.
3. Ograniczyć ujawnianie absolutnej ścieżki źródła w manifeście przeznaczonym do
   dystrybucji poza środowisko wewnętrzne.
4. Dodać komendę weryfikacji manifestu po przeniesieniu katalogu.
5. Dodać test kontrolowanego przerwania/awarii w każdej fazie publikacji.

### P2 — ergonomia i obserwowalność

1. Raportować czasy poszczególnych faz i podstawowe statystyki przepustowości.
2. Dodać dokumentowany tryb analizy samego źródła bez zapisu danych.
3. Rozszerzyć fixture o kolejne rzeczywiste warianty nagłówków i stron kodowych,
   nadal bez użycia danych produkcyjnych.

---

## 19. Definition of Done — lista kontrolna

Zmianę można uznać za gotową tylko wtedy, gdy odpowiedzi na wszystkie właściwe
pytania brzmią „tak”:

### Funkcjonalność

- [ ] Wszystkie DBF danych są odkrywane, również zduplikowane nazwy.
- [ ] Struktura podkatalogów jest zachowana.
- [ ] Ten sam tekst w różnych tabelach ma ten sam anonim.
- [ ] Mapowanie jest bijekcją bez punktów stałych.
- [ ] Długość bajtowa `C` jest zachowana w każdej stronie kodowej.
- [ ] `NULL`, puste wartości, deleted, kolejność i liczba rekordów są zachowane.
- [ ] `M/G`, `D/T` oraz `N/F/L` dają się dokładnie odwrócić.
- [ ] Recovery działa z właściwym słownikiem.
- [ ] Manifest obejmuje wszystkie DBF/FPT/CDX.

### VFP/CDX

- [ ] CDX jest znaleziony bez względu na wielkość liter.
- [ ] Skopiowany CDX służy tylko jako definicja.
- [ ] VFP wykonał `REINDEX`.
- [ ] Każdy tag można ustawić i wykonać `GO TOP`.
- [ ] Źródło, anonim i recovery otwierają się w VFP.
- [ ] Brak VFP lub błąd tagu blokuje publikację.

### Odporność

- [ ] Niepełny eksport nie buduje słownika.
- [ ] Błąd jednej tabeli nie publikuje częściowego wyniku.
- [ ] Poprzednia wersja wyniku i słownika przetrwała symulowany błąd.
- [ ] Rekonstrukcja workerów jest izolowana.
- [ ] `N(4,1)` z `-32` przechodzi regresję.
- [ ] Nagłówek kompaktowy z różnicą 263 bajtów przechodzi regresję.
- [ ] Naprawiony mismatch jest potwierdzony ponownym hashem.

### Bezpieczeństwo

- [ ] Logi nie zawierają treści pól ani memo.
- [ ] Słownik, dane, JSONL i logi nie są w Git staging.
- [ ] Słownik jest poza katalogiem anonimowym i ma ograniczony dostęp.
- [ ] Sól nie została wpisana do kodu, testu ani commita.
- [ ] Testy używają tylko danych syntetycznych.

### Jakość

- [ ] `python -m compileall -q src tests` przechodzi.
- [ ] `python -m pytest -ra` przechodzi.
- [ ] Windows CI 3.10/3.12/3.14 jest zielone.
- [ ] Test VFP został wykonany lub jawnie oznaczony jako niewykonany.
- [ ] Dokumentacja i `--help` odpowiadają kodowi.
- [ ] Każdy nowy błąd ma stabilny kod i test regresyjny.
- [ ] Diff nie zawiera zmian niezwiązanych z zadaniem.

---

## 20. Krótki szablon raportu końcowego dla modelu

Po wykonaniu lokalnej modyfikacji model powinien zwrócić raport w tym formacie:

```text
Wynik:
- co zostało zmienione i dlaczego;
- jaka była przyczyna źródłowa;
- jakie inwarianty projektu zostały zachowane.

Pliki:
- lista zmienionych plików i ich odpowiedzialność.

Walidacja:
- compileall: wynik;
- pytest: dokładna liczba passed/failed/skipped;
- Windows/VFP: wykonano / nie wykonano i dlaczego;
- self-test: polecenie, kod wyjścia, PASS/FAIL.

Bezpieczeństwo:
- potwierdzenie braku DBF/FPT/CDX/SQLite/JSONL/logów/soli w Git;
- potwierdzenie braku surowych wartości w nowych logach.

Ryzyka pozostałe:
- czego nie udało się potwierdzić;
- co operator powinien sprawdzić przed użyciem produkcyjnym.
```

Najważniejsza zasada całego projektu brzmi:

> Lepiej bezpiecznie przerwać konwersję z dokładnym kodem diagnostycznym niż
> opublikować szybki, częściowy albo nieodwracalny wynik.
