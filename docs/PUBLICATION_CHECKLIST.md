# Checklista publikacji repozytorium

Zmiana widoczności `private → public` jest osobną decyzją administracyjną. Nie
wykonuj jej automatycznie po samym scaleniu zmian w kodzie.

## 1. Bieżące drzewo

- pełny `pytest` i `compileall` przechodzą na Windows;
- test VFP/CDX przechodzi na kontrolowanym runnerze z rzeczywistym VFP 9;
- repozytorium nie zawiera DBF/FPT/CDX, słowników, `.env`, logów ani nazw
  własnych zbiorów danych;
- `.env.example` zawiera wyłącznie fikcyjne wartości;
- `LICENSE`, `README.md`, `SECURITY.md` i `CONTRIBUTING.md` są aktualne;
- dokumentacja opisuje odwracalną pseudonimizację, a nie gwarantowaną
  anonimizację prawną.

## 2. Historia i metadane GitHub

Samo usunięcie tekstu z `main` nie usuwa go z commitów, PR-ów, komentarzy,
gałęzi ani cache GitHub. Przed publikacją sprawdź co najmniej:

```powershell
git log --all --oneline --decorate
git log --all --format='%H %an <%ae> %s'
git rev-list --objects --all
git branch --all
```

Wyszukaj nazwy organizacji, ścieżki stanowisk, adresy e-mail, sekrety i dane
testowe także w zamkniętych PR-ach. Usunięcie gałęzi nie usuwa commitów już
osiągalnych z `main` lub refs PR.

Jeżeli historia zawiera informacje, których nie wolno ujawnić, najbezpieczniej
utworzyć nowe publiczne repozytorium z jednym zweryfikowanym commitem bieżącego
drzewa. Alternatywą jest kontrolowane przepisanie historii i force-push, ale
wymaga to kopii zapasowej, koordynacji wszystkich klonów oraz ponownego audytu;
nie gwarantuje usunięcia kopii i cache już udostępnionych usługom zewnętrznym.

## 3. Ustawienia przed zmianą widoczności

- ustaw opis repozytorium i tematy (`dbf`, `visual-foxpro`, `python`,
  `pseudonymization`, `sqlite`);
- włącz ochronę `main`, wymagany przegląd PR i wymagany workflow `tests`;
- włącz automatyczne usuwanie scalonych gałęzi;
- włącz Dependabot alerts/updates, secret scanning i push protection, jeżeli są
  dostępne dla repozytorium;
- zweryfikuj uprawnienia GitHub Actions oraz sekrety/zmienne self-hosted runnera;
- nie uruchamiaj kodu z `pull_request` na runnerze self-hosted; workflow VFP ma
  działać tylko ręcznie lub po pushu do chronionego `main`;
- ustaw adres commitów na publiczny adres `noreply`, jeżeli prywatny e-mail nie
  ma być widoczny w historii.

## 4. Ostatnia bramka

1. Pobierz świeży klon kandydata do publikacji.
2. Powtórz skan nazw własnych i sekretów oraz pełne testy.
3. Zweryfikuj zawartość artefaktu sdist/wheel.
4. Uzyskaj jawne zatwierdzenie właściciela danych i repozytorium.
5. Dopiero wtedy zmień widoczność na publiczną.
