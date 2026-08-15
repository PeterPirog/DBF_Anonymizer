# Instrukcja operacyjna (Windows + Visual FoxPro)

## Wymagania

- Windows 10/11 lub Windows Server.
- Python 3.10–3.14, środowisko projektu aktywne w PowerShell.
- Pełny Visual FoxPro z zarejestrowanym COM `VisualFoxPro.Application`, jeżeli
  choć jedna tabela ma strukturalny plik CDX.
- Wolne miejsce na katalog stagingowy, wynik, słownik i pośrednie JSONL.

Sprawdzenie VFP COM:

```powershell
$vfp = New-Object -ComObject VisualFoxPro.Application
$vfp.Version
$vfp.Quit()
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($vfp) | Out-Null
```

## Anonimizacja

Wersja minimalna — `workers=0` i pozostałe ustawienia domyślne są stosowane
automatycznie:

```powershell
dbf-anonymizer anonymize "D:\DANE_WOM\CWOM-B"
```

Powstaną katalogi `D:\DANE_WOM\CWOM-B_anonymized` oraz
`D:\DANE_WOM\CWOM-B_dict`.

Jeżeli podasz tylko `--out`, słownik nadal zostanie utworzony automatycznie obok
wyniku:

```powershell
dbf-anonymizer anonymize "D:\DANE_WOM\CWOM-B" `
  --out "D:\Warp_directory\CWOM-B_anonymized"
```

W tym przykładzie domyślny słownik trafi do
`D:\Warp_directory\CWOM-B_dict`. `--dict-dir` jest potrzebne wyłącznie wtedy,
gdy chcesz wskazać inną lokalizację.

Wersja z jawnymi opcjami operacyjnymi:

```powershell
chcp 65001
$env:PYTHONUTF8 = "1"
python -m dbf_anonymizer anonymize "D:\DANE_WOM\CWOM-B" `
  --out "D:\Warp_directory\CWOM-B_anonymized" `
  --dict-dir "D:\Warp_directory\CWOM-B_dictionary" `
  --salt "STAŁA-TAJNA-SÓL-DLA-TEJ-BAZY" `
  --workers 0 `
  --batch-size 5000 `
  --log-file "D:\Warp_directory\CWOM-B_anonymize.log"
```

Gdy źródłowy DBF ma odpowiadający mu CDX, brak Windows, COM VFP, tagów albo
błąd `REINDEX` kończy całą operację. Nowy wynik i słownik nie są publikowane;
poprzednia wersja pozostaje nienaruszona.

Domyślnie istniejący słownik jest rozszerzany, a wcześniejsze mapowania pól C
pozostają stabilne. Opcja `--fresh-dictionary` celowo zaczyna od zera. Przy
ponownym użyciu muszą zgadzać się sól, tryb memo, przesunięcie dat oraz zestaw
stron kodowych.

## Recovery i self-test

```powershell
python -m dbf_anonymizer recover `
  "D:\Warp_directory\CWOM-B_anonymized" `
  "D:\Warp_directory\CWOM-B_dictionary" `
  --out "D:\Warp_directory\CWOM-B_recovered" `
  --workers 0 `
  --log-file "D:\Warp_directory\CWOM-B_recover.log"

python -m dbf_anonymizer self-test "D:\DANE_WOM\CWOM-B" `
  --salt "STAŁA-TAJNA-SÓL-DLA-TEJ-BAZY" `
  --workers 0 `
  --log-file "D:\Warp_directory\CWOM-B_self-test.log"
```

Self-test sprawdza wartości i kolejność rekordów, flagi deleted, liczbę
rekordów, a dla tabel z CDX także otwarcie źródła, anonimu i recovery w VFP,
liczbę/nazwy tagów oraz możliwość przejścia po każdym tagu.

## Diagnostyka

Każdy błąd ma stabilny kod w nawiasach, `phase`, `event`, ścieżkę tabeli i typ
wyjątku. Wklej cały plik logu; wartości tekstowe wrażliwe są zastępowane
skrótem SHA-256. Najważniejsze kody:

Jeżeli proces roboczy zwróci błąd bez podniesienia wyjątku, log zawiera osobny
wpis `event=file_failed` dla każdej przyczyny z `path`, `table`, `error_index`,
`error_count` i `error_code`. `event=publication_blocked` wymienia wszystkie
tabele blokujące atomową publikację, a końcowy `phase=cli event=done` zapisuje
kod wyjścia polecenia. Dzięki temu do analizy wystarcza sam pełny plik logu.

| Kod | Znaczenie |
|---|---|
| `CDX_REINDEX_FAILED` | kopiowanie definicji, otwarcie VFP lub REINDEX nie powiodły się |
| `VFP_AUTOMATION_FAILED` | COM VFP zwrócił błąd; szczegóły są w `error=` |
| `RAW_PATCH_*` | nie można bezpiecznie przywrócić surowych N/F/L |
| `INCOMPLETE_EXPORT` | co najmniej jedna tabela nie została wyeksportowana |
| `GLOBAL_MAPPING_MISSING` | anonim nie istnieje w przekazanym słowniku |
| `INCREMENTAL_DICTIONARY_CONFIG_MISMATCH` | słownik pochodzi z innej konfiguracji |

Manifest `dbf_anonymizer_manifest.json` zawiera listę opublikowanych artefaktów
DBF/FPT/CDX, rozmiary i SHA-256.
