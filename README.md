# DBF_Anonymizer

Framework do anonimizacji plików DBF (Visual FoxPro 9.0) z odwracalnym słownikiem.

Narzędzie zastępuje dane we wszystkich plikach `.dbf` w katalogu źródłowym, tworząc
katalog wyjściowy z **identyczną strukturą plików DBF**, ale z zaanonimizowanymi danymi.
Słownik (`dictionary_<nazwa>.json` per tabela) pozwala odtworzyć oryginalne wartości.

## Zasady anonimizacji

| Typ pola DBF | Zachowanie |
|---|---|
| **C** (Character) | Zastąpione ciągiem o **identycznej długości bajtowej** (cp1250), deterministycznie (sha256+salt). Kolumny unikalne pozostają unikalne (bijekcja). |
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
  → save_dictionary (słownik oryginał↔anonim)

Recovery (odwrotny):
DBF zaanonimizowany
  → export_dbf → JSONL
  → recover_records (przywrócenie oryginałów ze słownika)
  → reconstruct_dbf → DBF zrekonstruowany
```

**Kluczowe:** `__dbfbridge_raw_record__` (base64 surowych bajtów DBF) jest usuwane
z rekordów, by `reconstruct_dbf` zbudował DBF z zaanonimizowanych wartości pól.
Bez tego reconstruct odtworzyłby oryginalne bajty byte-identically.

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

## CLI

```bash
# Anonimizuj katalog → <dir>_anonymized + <dir>_dict
dbf-anonymizer anonymize <dir> [--out OUT] [--dict-dir DICT] \
    [--memo mask|keep] [--date-offset N] [--salt S]

# Odtwórz oryginał z zaanonimizowanego + słowników → <anon>_recovered
dbf-anonymizer recover <anonymized_dir> <dictionary_dir> [--out OUT]

# Self-test: round-trip source → anonymized → recovered, porównanie kanoniczne
dbf-anonymizer self-test <dir> [--memo mask|keep] [--date-offset N] [--salt S]
```

Można też uruchomić przez `python -m dbf_anonymizer <command>`.

### Przykłady

```bash
# Anonimizacja z maskowaniem memo i przesunięciem dat o 30 dni
dbf-anonymizer anonymize E:\data\bok --memo mask --date-offset 30 --salt "proj-2024"

# Recovery (wymaga katalogu zaanonimizowanego i słowników)
dbf-anonymizer recover E:\data\bok_anonymized E:\data\bok_dict

# Self-test — weryfikacja round-trip
dbf-anonymizer self-test E:\data\bok
```

## Python API

```python
from dbf_anonymizer import anonymize_directory, make_dbf_recovery, self_test

# Anonimizacja
result = anonymize_directory(
    "E:/data/bok",
    memo_mode="mask",       # 'mask' lub 'keep'
    date_offset_days=30,    # 0 = bez zmian
    salt="my-secret",
)
print(f"OK={result.ok}, błędy={result.failed}")
# Wynik: result.output (katalog _anonymized), result.dictionary_dir (katalog _dict)

# Recovery
rec = make_dbf_recovery(result.output, result.dictionary_dir)
# Wynik: rec.output (katalog _recovered)

# Self-test (round-trip + porównanie kanoniczne)
report = self_test("E:/data/bok", memo_mode="mask")
print(f"PASS: {report.successful}, dopasowania: {report.canonical_matches}")
```

## Słownik (SENSITIWNY!)

Plik `dictionary_<nazwa_tabeli>.json` zawiera mapowanie oryginał↔anonim dla pól C
oraz oryginalne wartości M/G (w trybie `mask`). Pozwala odtworzyć pierwotne dane.

**Słownik jest w `.gitignore`** — NIE wysyłaj go na GitHub/serwer!

Struktura słownika:
```json
{
  "table": "klienci.dbf",
  "relative_path": "klienci.dbf",
  "options": {"memo_mode": "mask", "date_offset_days": 30, "text_mode": "same_length"},
  "fields": {
    "ID": {"name": "ID", "dbf_type": "C", "unique": true, "values": {"K001": "AB3X9K2PQR", ...}},
    "NAME": {"name": "NAME", "dbf_type": "C", "unique": false, "values": {"Jan Kowalski": "XK7M2N...", ...}},
    "BORN": {"name": "BORN", "dbf_type": "D", "offset_days": 30},
    "NOTE": {"name": "NOTE", "dbf_type": "M", "memo_mode": "mask", "memo_originals": ["Klient VIP", ...]}
  }
}
```

## Self-test

Self-test wykonuje pełny round-trip i weryfikuje kanoniczną identyczność
źródłowego DBF z zrekonstruowanym:

- Liczba rekordów (w tym deleted)
- Kolejność rekordów
- Wartości wszystkich pól danych
- Flagi `__deleted__`

```bash
dbf-anonymizer self-test E:\data\bok
# WYNIK: PASS — wszystkie tabele round-trip kanonicznie identyczne.
```

## Testy

```bash
pytest                    # wszystkie 40 testów
pytest tests/test_pipeline.py -v   # testy round-trip
```

Testy obejmują:
- `test_transforms.py` — mask_char (długość bajtowa, determinizm), memo, date shift/recover
- `test_uniqueness.py` — detekcja unikalnych kolumn, bijekcja, polskie znaki
- `test_pipeline.py` — round-trip self-test (mask/keep, date offset, salt, multi-table),
  struktura wyjścia, słowniki, unikalność po anonimizacji

Fixture DBF generowane przez bibliotekę `dbf` (VfpTable, cp1250, memo, polskie znaki,
deleted records, kolumny unikalne i nieunikalne).

## Architektura

```
src/dbf_anonymizer/
  __init__.py     — public API
  __main__.py     — python -m entry point
  cli.py          — argparse CLI (anonymize/recover/self-test)
  pipeline.py     — anonymize_directory, make_dbf_recovery, self_test
  anonymizer.py   — anonymize_records/recover_records (per-tabela)
  schema.py       — ładowanie _schema.json z dbfbridge
  transforms.py   — mask_char, mask_memo, shift_date, identity (+ odwrotności)
  uniqueness.py   — detekcja unikalnych kolumn C, bijekcja
  dictionary.py   — zapis/odczyt dictionary_*.json
tests/
  conftest.py     — fixture DBF (klienci.dbf, produkty.dbf)
  test_transforms.py
  test_uniqueness.py
  test_pipeline.py
```

## .gitignore

Repozytorium ignoruje:
- `dictionary_*.json` — słowniki (SENSITIWNE)
- `*_anonymized/`, `*_recovered/` — katalogi wyjściowe
- `var/` — pośrednie JSONL
- `*.dbf`, `*.fpt`, `*.cdx` — pliki DBF (nie wysyłaj danych przez git)

## Licencja

MIT
