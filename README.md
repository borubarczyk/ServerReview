# ServerReview – Przegląd serwerów

Narzędzie z interfejsem graficznym (WPF) do zbiorczego audytu serwerów Windows w domenie. Łączy się równolegle przez WinRM ze wszystkimi serwerami z listy i zbiera stan systemu oraz konfigurację bezpieczeństwa. Wskazuje problemy i pokazuje, co zmieniło się od poprzedniego skanu.

Cały program to jeden plik `ServerReview.ps1`. Nie wymaga instalacji ani dodatkowych modułów, a na serwerach niczego nie instaluje ani nie zmienia.

## Spis treści

- [Co sprawdza](#co-sprawdza)
- [Wymagania](#wymagania)
- [Uruchomienie](#uruchomienie)
- [Pierwsze kroki](#pierwsze-kroki)
- [Interfejs](#interfejs)
- [Wykrywane problemy](#wykrywane-problemy)
- [Porównanie z poprzednim skanem](#porównanie-z-poprzednim-skanem)
- [Raport HTML](#raport-html)
- [Ustawienia](#ustawienia)
- [Pliki programu](#pliki-programu)
- [Rozwiązywanie problemów](#rozwiązywanie-problemów)
- [Licencja](#licencja)

## Co sprawdza

| Obszar | Zbierane dane |
|---|---|
| **System** | uptime, oczekujący restart, data ostatniej aktualizacji, obciążenie CPU, użycie RAM i pamięci wirtualnej, zainstalowane role, serwer WSUS, antywirus, źródło czasu i różnica zegara względem stacji, koniec wsparcia systemu |
| **Stabilność** | błędy i zdarzenia krytyczne z dzienników System, Application i Hyper-V, historia restartów, awarie BSOD i pliki zrzutów pamięci, zajętość dysków, zdrowie dysków fizycznych i błędy dyskowe, rozmiar dzienników i okres, który obejmują |
| **Bezpieczeństwo** | podstawowy hardening (SMBv1, podpisywanie SMB, NLA, WDigest, poziom LM/NTLM, ochrona LSA, UAC, LLMNR, autologowanie, LAPS, SSL/TLS, PowerShell 2.0, Defender, zapora), zdarzenia bezpieczeństwa (nieudane logowania, blokady, zmiany kont i grup, czyszczenie dzienników, nowe usługi i zadania), polityka audytu, reguły zapory wpuszczające wrażliwe porty, subskrypcje WMI i wykluczenia Defendera, grupy uprzywilejowane, konta lokalne, certyfikaty, udziały, autostart |
| **Usługi, sieć i pliki** | usługi (spoza Microsoft, zatrzymane automatyczne, działające na kontach użytkowników, z niecytowaną ścieżką), zadania harmonogramu spoza `\Microsoft\` z wynikiem ostatniego uruchomienia, karty sieciowe i adresacja, porty nasłuchujące i aktywne połączenia (z procesem i usługą), sesje użytkowników, zawartość wskazanych folderów |
| **Oprogramowanie** | zainstalowane programy, ostatnie aktualizacje (KB) |
| **Role serwera** | kontroler domeny (SYSVOL/DFSR, replikacja AD, podpisywanie LDAP i channel binding), Hyper-V (maszyny, checkpointy, dyski VM i zapas miejsca na ich wzrost) |

Sekcje kontrolera domeny i Hyper-V pokazują się tylko na serwerach z tą rolą.

## Wymagania

**Stacja, z której uruchamiasz program**

- Windows z Windows PowerShell 5.1 (interfejs korzysta z WPF). Uruchomienie z PowerShell 7 też działa, bo skrypt sam przełącza się wtedy na `powershell.exe`.
- Dostęp do Active Directory, jeśli chcesz pobierać listę serwerów przyciskiem „Pobierz z AD”.

**Serwery**

- Włączony WinRM (domyślnie włączony od Windows Server 2012), port TCP 5985.
- Konto z uprawnieniami administratora lokalnego. Bez nich nie da się m.in. odczytać dziennika Security.
- Kolektor ma obejścia dla PowerShell 4.0 (Windows Server 2012 R2 bez WMF 5.1).

## Uruchomienie

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ServerReview.ps1
```

Opcjonalnie możesz wskazać własny plik z listą serwerów:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ServerReview.ps1 -ServerListFile D:\listy\serwery.txt
```

`-ExecutionPolicy Bypass` dotyczy tylko tego jednego uruchomienia. Jeśli zasady wykonywania skryptów na stacji już na to pozwalają (np. `RemoteSigned`), wystarczy odblokować pobrany plik poleceniem `Unblock-File .\ServerReview.ps1` i uruchomić go jak każdy skrypt.

## Pierwsze kroki

1. **Dodaj serwery**, na jeden z trzech sposobów:
   - **Pobierz z AD** dodaje włączone konta komputerów z systemem serwerowym, które logowały się do domeny w ostatnich 60 dniach.
   - **Wczytaj listę** czyta plik TXT lub CSV. Bierze pierwszą wartość z każdej linii i pomija puste linie, linie zaczynające się od `#` oraz nagłówki typu `Name` czy `DNSHostName`.
   - Wpisz nazwy w polu pod listą serwerów. Kilka nazw możesz oddzielić przecinkiem, średnikiem lub spacją.

   Lista zapisuje się w `servers.txt` obok skryptu i wczytuje się przy następnym uruchomieniu.
2. **Wybierz konto** (opcjonalnie). Przycisk „Konto: bieżące” pozwala podać inne poświadczenia, a „Anuluj” w tym oknie wraca do bieżącego konta.
3. **Ustaw zakres zdarzeń** w polu „Zdarzenia z ostatnich … dni” (1–180) i kliknij **Skanuj wszystkie**. Trwający skan możesz przerwać tym samym przyciskiem.
4. **Przejrzyj wyniki.** Po starcie programu widoczne są wyniki ostatniego skanu zapisane na dysku.

## Interfejs

### Wszystkie serwery

- **Kafelki:** liczba serwerów, odpowiadających, bez połączenia, problemów krytycznych i ostrzeżeń.
- **Wykryte problemy:** lista problemów ze wszystkich serwerów z filtrem poziomu i filtrem tekstowym. Zaznaczony wiersz pokazuje pełną treść pod tabelą, a dwuklik otwiera serwer w sekcji, której problem dotyczy.
- **Stan serwerów:** jedna linia na serwer (system, uptime, CPU, RAM, najmniej wolnego miejsca na dysku, dni od aktualizacji, liczba problemów, czas skanu). Dwuklik otwiera szczegóły serwera.

### Szczegóły serwera

- **Nagłówek:** system i rola, znaczniki (uptime, IP, aktualizacje, oczekujący restart, antywirus, różnica czasu), obciążenie CPU i RAM, liczba problemów oraz przycisk **Skanuj ponownie** dla tego jednego serwera.
- **Lista sekcji:** plakietka przy każdej sekcji pokazuje liczbę pozycji, a jej kolor najpoważniejszy problem w sekcji.
- **Tabela sekcji:**
  - pole „Filtruj wiersze” przeszukuje wszystkie kolumny;
  - **Eksport CSV** zapisuje widoczne wiersze w kolejności z tabeli (separator `;`, UTF-8);
  - panel pod tabelą pokazuje pełną treść zaznaczonego wiersza i można ją stamtąd skopiować.

Wiersze wymagające uwagi są kolorowane: czerwony oznacza problem krytyczny, żółty ostrzeżenie, a niebieski informację.

### Sortowanie tabel

Wszystkie tabele można sortować kliknięciem w nagłówek kolumny:

- kolejne kliknięcia przełączają sortowanie: **rosnąco → malejąco → kolejność oryginalna**;
- **Shift+klik** dodaje kolejną kolumnę do sortowania;
- liczby porównywane są jak liczby, a wersje i adresy IP naturalnie (`10.0.2` przed `10.0.10`);
- puste pola zawsze trafiają na koniec, a kolumny z poziomem ważności sortują się od najpoważniejszych;
- sortowanie jest zapamiętywane osobno dla każdej tabeli i sekcji, więc zostaje po przełączeniu serwera i przy odświeżaniu w trakcie skanu.

### Lista serwerów

- Pole „Szukaj serwera” filtruje listę po nazwie.
- Klawisz **Delete** usuwa zaznaczony serwer z listy.
- Prawy klik otwiera menu z poleceniami: skanowanie tego serwera, połączenie RDP, Zarządzanie komputerem, Podgląd zdarzeń, Usługi oraz udział `C$`.

## Wykrywane problemy

Każdy problem ma jeden z trzech poziomów. Progi podane poniżej to wartości domyślne, które można zmienić w [Ustawieniach](#ustawienia).

**Krytyczny**

- brak połączenia z serwerem;
- mniej niż 10% wolnego miejsca na dysku;
- nieudane logowania z adresów publicznych, czyli logowanie jest prawdopodobnie dostępne z internetu;
- wyczyszczony dziennik zdarzeń;
- różnica czasu względem stacji co najmniej 300 s (limit Kerberos);
- system po końcu wsparcia Microsoft;
- dysk fizyczny w stanie awarii;
- co najmniej 2 awarie BSOD w analizowanym okresie;
- krytyczne ustawienia bezpieczeństwa: wyłączona ochrona w czasie rzeczywistym, sygnatury antywirusa starsze niż 7 dni, włączony WDigest, autologowanie z zapisanym hasłem, jawnie włączone SSL 2.0/3.0;
- kontroler domeny: błąd replikacji SYSVOL (DFSR), replikacja AD bez sukcesu od ponad doby, krytyczne zdarzenia replikacji.

**Ostrzeżenie**

- mniej niż 20% wolnego miejsca na dysku;
- uptime powyżej 45 dni, oczekujący restart, brak aktualizacji od ponad 45 dni;
- użycie RAM lub pamięci wirtualnej co najmniej 90%, zdarzenia wyczerpania pamięci;
- zatrzymane usługi automatyczne, niecytowane ścieżki usług, nieudane zadania harmonogramu;
- zdarzenia krytyczne w dziennikach, nieoczekiwane wyłączenia, pliki zrzutów pamięci;
- co najmniej 25 nieudanych logowań, zmiany kont i członkostwa w grupach, włączone konto Gość;
- certyfikaty wygasające w ciągu 30 dni, checkpointy Hyper-V starsze niż 7 dni, problemy z heartbeatem lub replikacją VM;
- dysk dynamiczny VM, który może urosnąć ponad wolne miejsce na wolumenie;
- pełny dziennik zdarzeń, dziennik Security obejmujący krótszy okres niż analiza, niepełna polityka audytu;
- zużycie SSD co najmniej 90%, nieskorygowane błędy dysków, ponowienia operacji dyskowych;
- porty wrażliwe otwarte z dowolnego adresu, gdy karta sieciowa jest w profilu Publicznym;
- subskrypcje WMI uruchamiające polecenia lub skrypty (możliwy mechanizm trwałości);
- różnica czasu co najmniej 60 s, kontroler PDC bez zewnętrznego źródła czasu;
- ustawienia hardeningu oznaczone jako „Uwaga”, np. włączony SMBv1, RDP bez NLA, wyłączony UAC;
- nowe pozycje od poprzedniego skanu.

**Info**

- podsumowanie błędów w dziennikach, zainstalowane usługi, nowe lub zaktualizowane oprogramowanie z ostatnich 14 dni;
- konta z hasłem bez wygasania, osierocone SID-y w grupach, wygasłe certyfikaty;
- udziały z zapisem dla Wszystkich, pliki wykonywalne w sprawdzanych folderach;
- wyłączone maszyny wirtualne, rozłączone sesje, połączenia przychodzące z adresów publicznych, wykluczenia Defendera;
- zbliżający się koniec wsparcia systemu (365 dni);
- sekcje, których nie udało się zebrać na danym serwerze.

## Porównanie z poprzednim skanem

Każdy skan zapisuje migawkę danych serwera w pliku JSON. Kolejny skan porównuje się z poprzednim i w sekcji **Zmiany od poprzedniego skanu** pokazuje nowe oraz usunięte pozycje w obszarach:

- usługi spoza Microsoft;
- zadania harmonogramu;
- porty nasłuchujące;
- grupy uprzywilejowane i konta lokalne;
- udziały;
- autostart;
- oprogramowanie;
- subskrypcje WMI i wykluczenia AV;
- reguły zapory.

Nowe pozycje są zgłaszane jako ostrzeżenia, a w przypadku oprogramowania jako informacja. Sekcja pominięta w którymkolwiek z porównywanych skanów nie jest porównywana.

## Raport HTML

Przycisk **Raport HTML** zapisuje raport w folderze `Reports` jako `Przeglad_serwerow_RRRRMMDD_GGMM.html` i otwiera go w przeglądarce. Raport zawiera:

- kafelki z podsumowaniem i listę wszystkich problemów;
- zwijane szczegóły każdego serwera ze wszystkimi sekcjami.

Wygląd dopasowuje się do jasnego lub ciemnego motywu systemu, a raport nadaje się do druku.

## Ustawienia

Przycisk ⚙ otwiera okno ustawień. Zmiany zapisują się w pliku `settings.json` obok skryptu i nadpisują wartości domyślne z bloku `$Config` na początku skryptu. Przycisk „Przywróć domyślne” wraca do tych wartości.

**Zakres skanu.** Odznaczone sekcje nie są zbierane ani porównywane, co skraca skan. Liczba pomijanych sekcji wyświetla się przy zębatce.

**Parametry i progi**

| Ustawienie | Domyślnie |
|---|---|
| Zakres zdarzeń [dni] | 7 |
| Limit pobieranych zdarzeń na dziennik | 3000 |
| Uwzględniaj ostrzeżenia z dzienników System/Application | nie |
| Dysk: ostrzeżenie / krytyczne poniżej [% wolnego] | 20 / 10 |
| RAM / pamięć wirtualna: ostrzeżenie od [%] | 90 / 90 |
| Uptime: ostrzeżenie powyżej [dni] | 45 |
| Aktualizacje: ostrzeżenie po [dniach] | 45 |
| Certyfikaty: ostrzeżenie na [dni] przed wygaśnięciem | 30 |
| Checkpoint Hyper-V: ostrzeżenie po [dniach] | 7 |
| Nieudane logowania: ostrzeżenie od [liczba] | 25 |
| Nowe oprogramowanie: z ostatnich [dni] | 14 |
| Różnica czasu: ostrzeżenie / krytyczne od [s] | 60 / 300 |
| Koniec wsparcia systemu: uprzedzaj [dni] wcześniej | 365 |
| Zużycie SSD: ostrzeżenie od [%] | 90 |
| Ponowienia/resety I/O dysku: ostrzeżenie od [liczba] | 10 |
| BSOD: krytyczne od [liczba w okresie] | 2 |
| Ile serwerów skanować równolegle | 25 |
| Limit czasu całego skanu [s] | 900 |
| Ile migawek każdego serwera przechowywać | 30 |
| Foldery sprawdzane na serwerach | `C:\Temp`, `C:\Windows\Temp`, `C:\Users\Public\Downloads`, `C:\Install`, `C:\Scripts` |
| Usługi automatyczne, których zatrzymanie jest OK | lista usług systemowych (obsługuje wildcardy `*`) |
| Porty wrażliwe dla sekcji Ekspozycja | 21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986 |
| Subskrypcje WMI traktowane jako systemowe | subskrypcje obecne w czystym systemie |

Pole „Zdarzenia z ostatnich … dni” w głównym oknie zmienia zakres tylko dla bieżącego skanu.

Wymagane podkategorie polityki audytu (`AuditRequired`) i daty końca wsparcia systemów (`OsSupportEnd`) nie mają pól w oknie ustawień. Zmienia się je bezpośrednio w bloku `$Config` w skrypcie.

## Pliki programu

Program trzyma wszystkie dane w folderze, w którym leży skrypt:

```text
ServerReview.ps1
servers.txt                                  lista serwerów
settings.json                                ustawienia z okna Ustawienia
Snapshots\RRRRMMDD_GGMMSS\<serwer>.json      migawki skanów
Reports\Przeglad_serwerow_RRRRMMDD_GGMM.html raporty HTML
```

Jeśli skrypt uruchomiono bez pliku (np. wklejony do konsoli), zamiast folderu skryptu używany jest `%USERPROFILE%\Documents\ServerReview`.

Dla każdego serwera przechowywanych jest domyślnie 30 ostatnich migawek. Starsze są usuwane po skanie, a puste foldery skanów znikają.

## Rozwiązywanie problemów

- **Brak połączenia z serwerem.** Sprawdź WinRM poleceniem `Test-WSMan SRV01`. Na serwerze włączysz go przez `Enable-PSRemoting -Force`, a zapora musi przepuszczać port 5985.
- **Serwer dodany po adresie IP.** WinRM wymaga wtedy wpisu w TrustedHosts na stacji i podania konta przyciskiem „Konto”:

  ```powershell
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value 10.0.0.5 -Concatenate
  ```

- **„Przekroczono limit czasu”.** Zwiększ limit czasu skanu w ustawieniach albo odznacz najwolniejsze sekcje, np. połączenia, oprogramowanie lub foldery.
- **Puste zdarzenia bezpieczeństwa.** Konto musi mieć uprawnienia administratora na serwerze. Sekcja **Polityka audytu** pokazuje, których zdarzeń system w ogóle nie rejestruje.
- **Informacja „Nie udało się zebrać: …”.** Jedna sekcja nie zadziałała na danym serwerze, np. brak modułu w starszym systemie. Pozostałe dane są kompletne.
- **Popsute polskie znaki po edycji skryptu.** Zapisuj plik jako UTF-8 z BOM, bo Windows PowerShell 5.1 bez BOM odczytuje go w złym kodowaniu.

### Czy program coś zmienia na serwerach?

Nie, tylko odczytuje dane. Jedyny zapis to tymczasowy plik z wynikiem `auditpol /backup` w folderze `%TEMP%` serwera, usuwany zaraz po odczytaniu.

## Licencja

Copyright (C) 2026 Borys Kaleta

Program jest udostępniony na licencji [GNU General Public License v3.0](LICENSE) lub, według Twojego wyboru, dowolnej późniejszej wersji. W skrócie:

- możesz go używać, modyfikować i rozpowszechniać;
- jeśli rozpowszechniasz program lub jego zmodyfikowaną wersję, musisz udostępnić kod źródłowy na tej samej licencji;
- program dostarczany jest bez jakiejkolwiek gwarancji.

Wiążący jest pełny tekst licencji w pliku [LICENSE](LICENSE).
