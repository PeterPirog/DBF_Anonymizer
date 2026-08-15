# Bezpieczeństwo słownika

`dictionary.sqlite3` zawiera dane pozwalające odwrócić anonimizację: pełne
oryginały pól C i, w trybie `memo=mask`, wartości M/G. Jest materiałem
wrażliwym, a nie częścią bezpiecznego wyniku anonimowego.

- Nie commituj słownika ani jego plików `-wal`, `-shm`, `-journal`.
- Przechowuj go poza katalogiem synchronizowanym z GitHubem.
- Ogranicz ACL do konta/operatorów wykonujących recovery.
- Szyfruj nośnik i kopie zapasowe (np. BitLocker); przy przesyłaniu używaj
  szyfrowanego archiwum i oddzielnego kanału dla hasła.
- Sól powinna być stała dla kolejnych konwersji tej samej bazy, długa i tajna.
  Sól stabilizuje deterministyczny przydział nowych pseudonimów, ale nie
  zastępuje ochrony słownika.
- Logi nie zawierają pełnych brakujących wartości tekstowych. Traktuj jednak
  ścieżki, nazwy tabel i traceback jako informacje wewnętrzne.
- `.env` może zawierać sól i prywatne ścieżki. Jest ignorowany przez Git;
  commitowany ma być wyłącznie pozbawiony sekretów `.env.example`.
- `DBF_ANON_EXCLUDE` usuwa wskazane tabele z wyniku. Każde wykluczenie należy
  uzasadnić operacyjnie i sprawdzić w `excluded_tables` manifestu; nie może ono
  zastępować naprawy brakującego CDX czynnej tabeli aplikacyjnej.

Przed usunięciem słownika wykonaj i zachowaj wynik `self-test`; bez słownika
recovery pól C i zamaskowanych memo jest niemożliwe.
