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

Szablon jest przygotowany dla źródła `C:\Data\LegacyDB`, wyniku i słownika
w `C:\DBF_Work`, VFP pod
`C:\Program Files (x86)\Microsoft Visual FoxPro 9\vfp9.exe` oraz automatycznej
liczby procesów (`DBF_ANON_WORKERS=0`). Po zapisaniu konfiguracji wystarczy:

```powershell
dbf-anonymizer anonymize
```

Analogicznie `dbf-anonymizer recover` i `dbf-anonymizer self-test` pobierają
brakujące ścieżki z `.env`. Argument podany w poleceniu zastępuje wartość
domyślną. Zmienna już ustawiona w PowerShell ma pierwszeństwo przed plikiem.
Nie commituj `.env`; może zawierać tajną sól i prywatne ścieżki.

Przykładowe ścieżki w tym dokumencie są fikcyjne. Nie wpisuj rzeczywistych nazw
organizacji ani systemów do plików śledzonych przez Git.

## Anonimizacja

Wersja minimalna — `workers=0` i pozostałe ustawienia domyślne są stosowane
automatycznie:

```powershell
dbf-anonymizer anonymize "C:\Data\LegacyDB"
```

Powstaną katalogi `C:\Data\LegacyDB_anonymized` oraz
`C:\Data\LegacyDB_dict`.

Jeżeli podasz tylko `--out`, słownik nadal zostanie utworzony automatycznie obok
wyniku:

```powershell
dbf-anonymizer anonymize "C:\Data\LegacyDB" `
  --out "C:\DBF_Work\LegacyDB_anonymized"
```

W tym przykładzie domyślny słownik trafi do
`C:\DBF_Work\LegacyDB_dict`. `--dict-dir` jest potrzebne wyłącznie wtedy,
gdy chcesz wskazać inną lokalizację.

Wersja z jawnymi opcjami operacyjnymi:

```powershell
chcp 65001
$env:PYTHONUTF8 = "1"
python -m dbf_anonymizer anonymize "C:\Data\LegacyDB" `
  --out "C:\DBF_Work\LegacyDB_anonymized" `
  --dict-dir "C:\DBF_Work\LegacyDB_dict" `
  --salt "STAŁA-TAJNA-SÓL-DLA-TEJ-BAZY" `
  --workers 0 `
  --batch-size 5000 `
  --log-file "C:\DBF_Work\LegacyDB_anonymize.log"
```

Gdy źródłowy DBF ma odpowiadający mu CDX, brak Windows, COM VFP, tagów albo
błąd `REINDEX` kończy całą operację. Nowy wynik i słownik nie są publikowane;
poprzednia wersja pozostaje nienaruszona.

Kontrola brakujących indeksów odbywa się przed eksportem. Bajt 28 nagłówka
jest maską: `0x01` = strukturalny CDX, `0x02` = FPT, `0x04` = DBC.
`SOURCE_CDX_MISSING` oznacza, że ustawiony jest bit `0x01`, ale obok nie ma
CDX o tym samym rdzeniu. Sam bit `0x02` oraz para DBF+FPT bez CDX są prawidłowe.
Dla tabeli rzeczywiście oznaczonej `0x01` należy przywrócić właściwy CDX z
kopii źródłowej. `FOXUSER.DBF` jest domyślnie pomijany jako zasób ustawień VFP.

Świadome pominięcie dodatkowej tabeli jest możliwe przez `.env`:

```dotenv
DBF_ANON_EXCLUDE=ARCHIWUM/stara_tabela.dbf
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
  "C:\DBF_Work\LegacyDB_anonymized" `
  "C:\DBF_Work\LegacyDB_dict" `
  --out "C:\DBF_Work\LegacyDB_recovered" `
  --workers 0 `
  --log-file "C:\DBF_Work\LegacyDB_recover.log"

python -m dbf_anonymizer self-test "C:\Data\LegacyDB" `
  --salt "STAŁA-TAJNA-SÓL-DLA-TEJ-BAZY" `
  --workers 0 `
  --log-file "C:\DBF_Work\LegacyDB_self-test.log"
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
| `SOURCE_CDX_MISSING` | bit `0x01` maski tabeli wymaga strukturalnego CDX, ale pliku brak; samo `0x02`/FPT nie jest błędem |
| `DBF_HEADER_TRUNCATED` | nie można bezpiecznie odczytać pełnego bajtu flag; eksport jest blokowany |
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
Pole `source` zawiera tylko nazwę katalogu, nie bezwzględną ścieżkę operatora.
