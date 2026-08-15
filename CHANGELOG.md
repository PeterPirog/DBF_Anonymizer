# Historia zmian

## 0.3.1 — 2026-08-15

- usunięto nazwy własne i prywatne ścieżki z bieżącego drzewa projektu;
- diagnostyka self-testu nie ujawnia wartości pól, tylko typ, długość i SHA-256;
- manifest v2 zapisuje nazwę źródła bez bezwzględnej ścieżki operatora;
- blokowane są wszystkie nakładające się katalogi źródła, wyniku, słownika i
  recovery;
- dodano licencję, zasady współpracy, politykę zgłaszania luk i checklistę
  publikacji repozytorium;
- dodano testy ochronne dla danych diagnostycznych i nazw własnych.
- utwardzono workflow self-hosted i dodano audyt zależności oraz skan statyczny.
- wewnętrzny kontekst lokalnego agenta zastąpiono publiczną dokumentacją
  architektury i wykluczono z kontroli wersji.

## 0.3.0 — 2026-08-15

- transakcyjny pipeline wielu tabel z globalnym słownikiem SQLite;
- strumieniowe JSONL, multiprocessing i trwałe mapowania;
- obsługa DBF/FPT oraz strukturalnych CDX z obowiązkowym `REINDEX` w VFP;
- pełny round-trip i self-test kanoniczny.
