# Benchmarki

Mikrobenchmark SQLite uruchamiaj w tym samym środowisku i na tym samym dysku,
na którym będzie konwersja:

```powershell
python benchmarks\benchmark_sqlite.py --values 1000000 --batch-size 10000
```

Zapisz: wersję projektu/Pythona, CPU, rodzaj dysku, rozmiar partii, liczbę
wartości oraz pełny wynik skryptu. Pomiar obejmuje budowę bijekcji, wsadowe
odczyty, szczyt pamięci śledzonej przez Python i rozmiar SQLite.

Dla pełnego pipeline mierz osobno `anonymize`, `recover` i `self-test` poleceniem
`Measure-Command`. Porównuj te same dane i słownik. `--workers 0` ogranicza
liczbę procesów do liczby tabel; przy kilku wielkich tabelach obciążenie CPU
może być niższe, ponieważ eksport/rekonstrukcja są częściowo ograniczone I/O.

Nie publikuj danych wejściowych, słownika ani logów zawierających informacje o
wewnętrznej strukturze bazy razem z wynikiem benchmarku.
