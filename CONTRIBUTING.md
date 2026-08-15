# Współpraca przy projekcie

1. Utwórz osobną gałąź od aktualnego `main`.
2. Używaj wyłącznie syntetycznych fixture. Nie commituj produkcyjnych
   DBF/FPT/CDX, słowników, `.env`, logów ani nazw własnych systemów i klientów.
3. Dodaj test regresyjny dla każdej poprawki błędu.
4. Uruchom:

   ```powershell
   python -m compileall -q src tests
   python -m pytest -ra
   ```

5. Dla zmian CDX/VFP wykonaj również oznaczone testy na kontrolowanym runnerze
   Windows z Visual FoxPro 9. Nie publikuj fixture ani logów tego runnera i nie
   uruchamiaj na nim niezaufanego kodu z publicznego PR-a.
6. Otwórz PR z opisem ryzyka, kompatybilności formatu słownika i wyniku testów.

Zmiana formatu słownika, algorytmu mapowania lub zasad publikacji atomowej musi
być jawna i zgodna wstecznie albo otrzymać udokumentowaną migrację. Zgłoszenia
bezpieczeństwa kieruj zgodnie z [`SECURITY.md`](SECURITY.md).
