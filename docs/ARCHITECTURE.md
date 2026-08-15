# Architektura

## Cel i granice

Projekt wykonuje odwracalną pseudonimizację katalogu tabel Visual FoxPro.
Zachowuje układ podkatalogów, schematy DBF, relacje tekstowe, rekordy usunięte,
FPT oraz strukturalne indeksy CDX. Nie modyfikuje formularzy, raportów ani
kontenerów projektów VFP.

## Przepływ danych

1. Pipeline rekurencyjnie odkrywa tabele i wykonuje preflight nagłówków/CDX.
2. Każdy DBF jest eksportowany do izolowanego, strumieniowego JSONL i schematu.
3. Jeden proces buduje globalną bijekcję tekstów w `dictionary.sqlite3`.
4. Workery czytają słownik tylko do odczytu, transformują partie rekordów i
   rekonstruują każdą tabelę w osobnym katalogu zadania.
5. Dla tabel ze strukturalnym CDX kopiowane są definicje tagów, po czym pełny
   Visual FoxPro wykonuje obowiązkowy `REINDEX` i test otwarcia.
6. Wynik oraz słownik są publikowane razem dopiero po sukcesie wszystkich tabel.

Recovery wykonuje odwrotne mapowanie z tego samego słownika. Self-test uruchamia
pełny cykl i porównuje źródło z recovery rekord po rekordzie.

## Inwarianty

- ten sam niepusty tekst ma jeden pseudonim w całej bazie;
- `original` i `anonymized` są unikalne, a mapowanie nie ma punktów stałych;
- pseudonim zachowuje długość bajtową w stronie kodowej tabeli;
- wartości diagnostyczne pól nie trafiają do logów — używane są typ, długość i
  SHA-256;
- katalogi źródła, wyniku, słownika i recovery nie mogą się pokrywać ani
  zawierać wzajemnie;
- pojedynczy błąd blokuje publikację całego nowego wyniku;
- skopiowany CDX bez udanego `REINDEX` nigdy nie jest wynikiem końcowym.

## Współbieżność

`workers=0` dobiera liczbę procesów automatycznie. Eksport i rekonstrukcja są
równoległe, ale zapis globalnej mapy jest pojedynczy i transakcyjny. Każda tabela
ma katalog zadania wyznaczony ze ścieżki względnej, dzięki czemu identyczne nazwy
plików w różnych podkatalogach nie kolidują na Windows.

## Granice zaufania

`dictionary.sqlite3`, lokalny `.env`, logi i dane tymczasowe są wrażliwe.
Manifest wyniku zawiera jedynie nazwę katalogu źródłowego i względne ścieżki.
Runner self-hosted z VFP nie wykonuje kodu pochodzącego bezpośrednio z
publicznych PR-ów. Szczegółowe zasady znajdują się w `docs/SECURITY.md` oraz
`docs/PUBLICATION_CHECKLIST.md`.
