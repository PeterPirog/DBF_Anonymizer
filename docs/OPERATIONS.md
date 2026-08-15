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

## Jednorazowa konfiguracja `.env`

W katalogu repozytorium:

```powershell
Copy-Item .env.example .env
notepad .env
```

Szablon jest przygotowany dla źródła `D:\DANE_WOM\CWOM-B`, wyniku i słownika
w `D:\Warp_directory`, VFP pod
`C:\Program Files (x86)\Microsoft Visual FoxPro 9\vfp9.exe` oraz automatycznej
liczby procesów (`DBF_ANON_WORKERS=0`). Po zapisaniu konfiguracji wystarczy:

```powershell
dbf-anonymizer anonymize
```

Analogicznie `dbf-anonymizer recover` i `dbf-anonymizer self-test` pobierają
brakujące ścieżki z `.env`. Argument podany w poleceniu zastępuje wartość
domyślną. Zmienna już ustawiona w PowerShell ma pierwszeństwo przed plikiem.
Nie commituj `.env`; może zawierać tajną sól i prywatne ścieżki.

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

Kontrola brakujących indeksów odbywa się przed eksportem. `SOURCE_CDX_MISSING`
oznacza, że nagłówek DBF wymaga strukturalnego CDX, ale obok nie ma pliku o tym
samym rdzeniu. Dla tabel aplikacyjnych należy przywrócić właściwy CDX z kopii
źródłowej. `FOXUSER.DBF` jest domyślnie pomijany jako zasób ustawień VFP.

Świadome pominięcie dodatkowej tabeli jest możliwe przez `.env`:

```dotenv
DBF_ANON_EXCLUDE=DANE/pomoc.dbf;ARCHIWUM/stara_tabela.dbf
```

Usuwa to te tabele z anonimizowanego wyniku i recovery. Każde wykluczenie trafia
do logu i manifestu. Nie stosuj go do czynnej tabeli tylko po to, aby uzyskać
zielony wynik.

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
| `SOURCE_CDX_MISSING` | DBF wymaga strukturalnego CDX, ale pliku brak; błąd wykryty przed eksportem |
| `VFP_EXECUTABLE_MISSING` | ścieżka `DBF_ANON_VFP_EXE` nie wskazuje istniejącego pliku |
| `VFP_AUTOMATION_FAILED` | COM VFP zwrócił błąd; szczegóły są w `error=` |
| `RAW_PATCH_*` | nie można bezpiecznie przywrócić surowych N/F/L |
| `HEADER_LAYOUT_*` | nie można bezpiecznie przywrócić źródłowego układu nagłówka VFP |
| `CANONICAL_MISMATCH_REPAIRED_BY_RAW_IDENTITY_PATCH` | różnice N/F/L naprawiono dokładnymi bajtami i potwierdzono ponowną sumą kanoniczną |
| `INCOMPLETE_EXPORT` | co najmniej jedna tabela nie została wyeksportowana |
| `GLOBAL_MAPPING_MISSING` | anonim nie istnieje w przekazanym słowniku |
| `INCREMENTAL_DICTIONARY_CONFIG_MISMATCH` | słownik pochodzi z innej konfiguracji |

Manifest `dbf_anonymizer_manifest.json` zawiera listę opublikowanych artefaktów
DBF/FPT/CDX, rozmiary, SHA-256 oraz audytowalną listę wykluczonych tabel.
