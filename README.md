# DBF_Anonymizer

Framework do anonimizacji plików DBF (Visual FoxPro 9.0) z odwracalnym słownikiem.

Narzędzie zastępuje dane we wszystkich plikach `.dbf` w katalogu źródłowym, tworząc
katalog wyjściowy z **identyczną strukturą plików DBF**, ale z zaanonimizowanymi danymi.
Wszystkie pola tekstowe `C` we wszystkich tabelach korzystają z jednego globalnego
słownika SQLite (`dictionary.sqlite3`). Ten sam tekst otrzymuje dokładnie ten sam
pseudonim niezależnie od nazwy tabeli, pola i katalogu, dlatego tekstowe klucze
główne/obce zachowują spójność relacyjną. Wynik jest budowany w stagingu i
publikowany razem ze słownikiem dopiero po sukcesie wszystkich tabel. JSONL jest
przetwarzany strumieniowo partiami, a kosztowne etapy działają równolegle.

Jeżeli tabela ma strukturalny CDX, narzędzie kopiuje go jako nośnik definicji
tagów, po czym **obowiązkowo wykonuje `REINDEX` w pełnym Visual FoxPro**. Błąd
VFP/CDX blokuje publikację całego katalogu.

## Zasady anonimizacji

| Typ pola DBF | Zachowanie |
|---|---|
| **C** (Character) | Zastąpione ciągiem o **identycznej długości bajtowej** w stronie kodowej tabeli, deterministycznie (sha256+salt). Kolumny unikalne pozostają unikalne (bijekcja). |
| **M / G** (Memo/General) | `mask` → `'MEMO'` (domyślnie), `keep` → bez zmian. Recovery przywraca oryginał pozycyjnie ze słownika. |
| **D** (Date) | Przesunięcie o stałą liczbę dni (`--date-offset N`, `0` = bez zmian). |
| **T** (DateTime) | Przesunięcie daty o N dni, czas bez zmian. |
| **N / F** (Numeric/Float) | Bez zmian (identity). |
| **L** (Logical) | Bez zmian (identity). |

Pola formularzy VFP (`.scx/.sct/.frx/.lbx/.mnx/.pjx/.vcx/.dbc`) są pomijane —
anonimizowane są tylko `.dbf` z danymi.

## Przepływ round-trip

```
DBF źródłowy
  → export_dbf (dbfbridge) → pośredni JSONL + _schema.json
  → anonymize_records (transformacja pól, usunięcie __dbfbridge_raw_record__)
  → zapis zaanonimizowanego JSONL
  → reconstruct_dbf (dbfbridge) → DBF zaanonimizowany
  → globalny dictionary.sqlite3 (oryginał↔anonim, UNIQUE w obu kierunkach)

Recovery (odwrotny):
DBF zaanonimizowany
  → export_dbf → JSONL
  → recover_records (przywrócenie oryginałów ze słownika)
  → reconstruct_dbf → DBF zrekonstruowany
```

**Kluczowe:** pełne `__dbfbridge_raw_record__` nie jest przekazywane do
rekonstrukcji, bo cofnęłoby anonimizację pól C. Po rekonstrukcji pipeline
przywraca z niego wyłącznie surowe bajty nietransformowanych pól `N/F/L`. Dzięki
temu zachowuje historyczne formy FoxPro, np. `-32` w `N(4,1)`, których ogólny
writer nie potrafi znormalizować do `-32.0`.

## Instalacja

```bash
git clone https://github.com/PeterPirog/DBF_Anonymizer.git
cd DBF_Anonymizer
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -e ".[dev]"
```

Wymaga Python ≥ 3.10. Zależności: `dbfbridge` (z [dbfbridge repo](https://github.com/PeterPirog/dbfbridge)),
`dbf>=0.99.11` (tylko do testów/reconstruct).

Dla źródeł z CDX wymagany jest Windows i zarejestrowany serwer COM pełnego
Visual FoxPro (`VisualFoxPro.Application`).

## CLI

```bash
# Anonimizuj katalog → <dir>_anonymized + <dir>_dict
dbf-anonymizer anonymize <dir> [--out OUT] [--dict-dir DICT] \
    [--memo mask|keep] [--date-offset N] [--salt S] [--workers N] \
    [--batch-size N] [--fresh-dictionary] [--vfp-progid PROGID] \
    [--log-level LEVEL] [--log-file FILE]

# Odtwórz oryginał z zaanonimizowanego + słowników → <anon>_recovered
dbf-anonymizer recover <anonymized_dir> <dictionary_dir> [--out OUT] \
    [--workers N] [--batch-size N] [--vfp-progid PROGID]

# Self-test: round-trip source → anonymized → recovered, porównanie kanoniczne
dbf-anonymizer self-test <dir> [--memo mask|keep] [--date-offset N] \
    [--salt S] [--workers N] [--batch-size N] [--vfp-progid PROGID]
```

Można też uruchomić przez `python -m dbf_anonymizer <command>`.

### Przykłady

```bash
# Anonimizacja z maskowaniem memo i przesunięciem dat o 30 dni
dbf-anonymizer anonymize D:\data\bok --memo mask --date-offset 30 --salt "proj-2024" --workers 4

# Recovery (wymaga katalogu zaanonimizowanego i słowników)
dbf-anonymizer recover D:\data\bok_anonymized D:\data\bok_dict

# Self-test — weryfikacja round-trip
dbf-anonymizer self-test D:\data\bok
```

`--workers 0` (wartość domyślna) automatycznie dobiera liczbę procesów,
`--workers 1` wymusza tryb sekwencyjny, a `--workers N` uruchamia maksymalnie N
procesów. Każdy plik ma izolowany katalog tymczasowy, więc zadania nie kolidują.

### Spójność relacyjna i SQLite

Przykładowo wartość `K001` w `klienci.ID`, `zamowienia.CLIENT_ID` oraz
`archiwum/klienci.ID` jest mapowana na jeden pseudonim. Mapowanie nie zawiera nazwy
tabeli ani pola w kluczu — kluczem jest dokładna wartość tekstowa. `NULL` i pusty
tekst pozostają bez zmian.

SQLite jest celowym wyborem zamiast dużego JSON lub Redis:

- indeksy `PRIMARY KEY`/`UNIQUE` gwarantują bijekcję i wykrywają kolizje;
- budowa używa jednego writera i transakcji, bez trzymania całej bazy w RAM;
- procesy robocze wykonują tylko wsadowe odczyty read-only;
- słownik jest jednym przenośnym, atomowo zapisanym plikiem — bez osobnego serwera;
- Redis nie jest potrzebny i utrudniałby trwały, odwracalny zapis końcowy.

Przy kolejnej anonimizacji do tego samego `--dict-dir` istniejące mapowania C są
domyślnie zachowywane, a metadane bieżących plików i pozycyjne memo odświeżane.
Sól, opcje i strony kodowe muszą być zgodne. `--fresh-dictionary` celowo tworzy
nową bijekcję.

Mapowanie zachowuje długość bajtową wartości. Jeżeli dla bardzo krótkiej długości
nie istnieje wystarczająco dużo różnych pseudonimów, konwersja kończy się błędem
`TEXT_DOMAIN_CAPACITY` zamiast utworzyć nieodwracalną kolizję. Alfabet nie jest
ograniczony do 36 liter/cyfr: powstaje z drukowalnych znaków jednobajtowych
wspólnych dla stron kodowych wykrytych w schematach DBF. Pomijane są białe znaki,
znaki kontrolne oraz oczywiste pary różniące się tylko wielkością liter.
Pseudonim nie może być identyczny z oryginałem. Jeżeli eksport choć jednej tabeli
się nie powiedzie, kodowanie pozostałych tabel nie rozpocznie się — globalny
słownik nigdy nie jest budowany na niepełnym obrazie bazy.

### Logi diagnostyczne

Domyślny poziom `INFO` pokazuje na bieżąco fazę, PID, liczbę plików i workerów,
postęp tabel, wykryte kodowania, rozmiar alfabetu oraz kontrolę pojemności. Pełny
log UTF-8 można zapisać opcją:

```powershell
python -m dbf_anonymizer anonymize "D:\DANE_WOM\CWOM-B" `
  --out "D:\Warp_directory\CWOM-B_anonymized" `
  --dict-dir "D:\Warp_directory\CWOM-B_dictionary" `
  --salt "TAJNA-STALA-SOL" --workers 0 `
  --log-level INFO `
  --log-file "D:\Warp_directory\CWOM-B_conversion.log"
```

Kody błędów, np. `TEXT_ENCODING_ERROR`, `INCONSISTENT_TEXT_BYTE_LENGTH` i
`TEXT_DOMAIN_CAPACITY`, zawierają kontekst tabeli/pola/kodowania bez wypisywania
pełnych wartości danych osobowych. Nieoczekiwane wyjątki zapisują traceback.

Każdy proces rekonstruuje DBF/FPT w osobnym katalogu zadania. Do katalogu
stagingowego trafiają wyłącznie artefakty danej tabeli; roboczy
`reconstruction_report.jsonl` nie jest współdzielony przez procesy. Zapobiega
to błędowi Windows `WinError 32` podczas równoległego przetwarzania wielu tabel
w tym samym katalogu. Cały staging i słownik są publikowane dopiero po
rekonstrukcji wszystkich tabel oraz REINDEX każdego CDX.

## Python API

```python
from dbf_anonymizer import anonymize_directory, make_dbf_recovery, self_test

if __name__ == "__main__":  # wymagane przez multiprocessing w Windows
    result = anonymize_directory(
        "E:/data/bok",
        memo_mode="mask",       # 'mask' lub 'keep'
        date_offset_days=30,    # 0 = bez zmian
        salt="my-secret",
        workers=4,             # None/0 = automatycznie, 1 = sekwencyjnie
    )
    print(f"OK={result.ok}, błędy={result.failed}")

    rec = make_dbf_recovery(result.output, result.dictionary_dir, workers=4)
    report = self_test("E:/data/bok", memo_mode="mask", workers=4)
    print(f"PASS: {report.successful}, dopasowania: {report.canonical_matches}")
```

## Globalny słownik SQLite (SENSITIWNY!)

Plik `dictionary.sqlite3` zawiera wspólne mapowanie oryginał↔anonim dla pól C
ze wszystkich tabel oraz oryginalne wartości M/G (w trybie `mask`) indeksowane
według ścieżki względnej, pola i numeru rekordu. Pozwala odtworzyć każdą tabelę.

**Słownik jest w `.gitignore`** — NIE wysyłaj go na GitHub/serwer!

Najważniejsze tabele wewnętrzne:

```text
text_map(original PRIMARY KEY, anonymized UNIQUE, byte_length)
text_sources(original, relative_path, field_name, encoding, byte_length)
memo_values(relative_path, field_name, record_index, value_json)
files(relative_path PRIMARY KEY, table_name)
metadata(key PRIMARY KEY, value_json)
```

Recovery nadal odczytuje starsze słowniki JSON v1/v2 i SQLite v3, ale nowe
anonimizacje tworzą format SQLite v4 z metadanymi kodowań i diagnostyką źródeł.

## Self-test

Self-test wykonuje pełny round-trip i weryfikuje kanoniczną identyczność
źródłowego DBF z zrekonstruowanym:

- Liczba rekordów (w tym deleted)
- Kolejność rekordów
- Wartości wszystkich pól danych
- Flagi `__deleted__`
- Otwarcie źródła, anonimu i recovery w VFP (dla tabel z CDX)
- Liczbę/nazwy tagów CDX oraz możliwość użycia każdego porządku

```bash
dbf-anonymizer self-test D:\data\bok
# WYNIK: PASS — wszystkie tabele round-trip kanonicznie identyczne.
```

## Testy

```bash
pytest                    # wszystkie testy
pytest tests/test_pipeline.py -v   # testy round-trip
```

Testy obejmują:
- `test_transforms.py` — mask_char (długość bajtowa, determinizm), memo, date shift/recover
- `test_uniqueness.py` — detekcja unikalnych kolumn, bijekcja, polskie znaki
- `test_pipeline.py` — round-trip, duplikaty nazw, multiprocessing oraz spójność
  klucza tekstowego między różnymi tabelami i polami
- `test_global_store.py` — bijekcja, determinizm i granice pojemności SQLite
- `test_atomicfs.py`, `test_rawpatch.py`, `test_vfp.py` — publikacja katalogów,
  regresja `N(4,1)` oraz kopiowanie definicji/REINDEX CDX

Pełny `pytest` uruchamia się w GitHub Actions na Windows. Realny test COM VFP
może działać na runnerze self-hosted z etykietami `Windows` i `vfp9` po ustawieniu
zmiennych repozytorium `VFP_SELF_HOSTED=true` i `VFP_FIXTURE_PATH` wskazującej
lokalny katalog testowy DBF/FPT/CDX na runnerze.

Dokumentacja: [operacje](docs/OPERATIONS.md),
[bezpieczeństwo słownika](docs/SECURITY.md),
[benchmarki](docs/BENCHMARKS.md).

Fixture DBF generowane przez bibliotekę `dbf` (VfpTable, cp1250, memo, polskie znaki,
deleted records, kolumny unikalne i nieunikalne).

## Architektura

```
src/dbf_anonymizer/
  __init__.py     — public API
  __main__.py     — python -m entry point
  cli.py          — argparse CLI (anonymize/recover/self-test)
  pipeline.py     — multiprocessing, anonymize_directory, make_dbf_recovery, self_test
  atomicfs.py     — staging i transakcyjna publikacja całych katalogów
  tableio.py      — strumieniowe partie JSONL i wsadowe lookupy SQLite
  rawpatch.py     — dokładne bajty nietransformowanych N/F/L
  vfp.py          — definicje CDX, COM VFP i obowiązkowy REINDEX
  verification.py— strumieniowy round-trip i test VFP/CDX
  manifest.py     — SHA-256 opublikowanych DBF/FPT/CDX
  anonymizer.py   — transformacje rekordów, anonymize_records/recover_records
  global_store.py — globalny dictionary.sqlite3, bijekcja i wsadowe lookupy
  schema.py       — ładowanie _schema.json z dbfbridge
  transforms.py   — mask_char, mask_memo, shift_date, identity (+ odwrotności)
  uniqueness.py   — detekcja unikalnych kolumn C, bijekcja
  dictionary.py   — zgodność wsteczna: odczyt/zapis dictionary_*.json v1/v2
tests/
  conftest.py     — fixture DBF (klienci.dbf, produkty.dbf)
  test_transforms.py
  test_uniqueness.py
  test_pipeline.py
```

## .gitignore

Repozytorium ignoruje:
- `dictionary.sqlite3*`, `dictionary_*.json` — słowniki (SENSITIWNE)
- `*_anonymized/`, `*_recovered/` — katalogi wyjściowe
- `var/` — pośrednie JSONL
- `*.dbf`, `*.fpt`, `*.cdx` — pliki DBF (nie wysyłaj danych przez git)

## Licencja

MIT
