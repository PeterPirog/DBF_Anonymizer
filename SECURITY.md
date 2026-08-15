# Zgłaszanie luk bezpieczeństwa

Nie zgłaszaj podatności zawierających dane produkcyjne w publicznym Issue.
Użyj prywatnego zgłoszenia w **Security → Advisories → New draft security
advisory** tego repozytorium. Opisz wersję, system, minimalny syntetyczny sposób
odtworzenia oraz wpływ błędu.

Nigdy nie dołączaj rzeczywistych plików DBF/FPT/CDX, `dictionary.sqlite3`,
lokalnego `.env`, soli, pełnych logów ani nazw organizacji. Jeżeli prywatne
advisories nie są dostępne, otwórz publiczny Issue bez szczegółów i poproś
maintainera o bezpieczny kanał kontaktu.

Projekt jest rozwijany na zasadzie best effort. Informacja o wspieranych
wersjach znajduje się w `pyproject.toml`; poprawki bezpieczeństwa są kierowane
do bieżącej wersji na `main`.
