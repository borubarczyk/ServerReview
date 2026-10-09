# ServerReview – Przegląd serwerów

Narzędzie z interfejsem graficznym (WPF) do zbiorczego audytu serwerów Windows w domenie. Łączy się równolegle przez WinRM ze wszystkimi serwerami z listy, zbiera stan systemu, konfigurację bezpieczeństwa i dane Hyper-V, wskazuje problemy i pokazuje, co zmieniło się od poprzedniego skanu. Gdy serwer nie odpowiada, program sam diagnozuje przyczynę i zapisuje ją w dzienniku dostępności.

Program jest przygotowany na większe środowiska: kilkaset serwerów, w tym kilkanaście–kilkadziesiąt hostów Hyper-V z maszynami wirtualnymi. Skanuje tylko Windows. Maszyny z Linuksem rozpoznaje na hostach Hyper-V i pomija.

Cały program to jeden plik `ServerReview.ps1`. Nie wymaga instalacji ani dodatkowych modułów, a na serwerach niczego nie instaluje ani nie zmienia.

## Spis treści

- [Co sprawdza](#co-sprawdza)
- [Wymagania](#wymagania)
- [Uruchomienie](#uruchomienie)
- [Pierwsze kroki](#pierwsze-kroki)
- [Interfejs](#interfejs)
- [Niedostępne serwery](#niedostępne-serwery)
- [Hyper-V i klastry](#hyper-v-i-klastry)
- [Wykrywane problemy](#wykrywane-problemy)
- [Wyciszanie problemów](#wyciszanie-problemów)
- [Porównanie z poprzednim skanem](#porównanie-z-poprzednim-skanem)
- [Raport HTML](#raport-html)
- [Dziennik operacji i dziennik dostępności](#dziennik-operacji-i-dziennik-dostępności)
- [Blokada programu (PIN)](#blokada-programu-pin)
- [Ustawienia](#ustawienia)
- [Pliki programu](#pliki-programu)
- [Duże środowiska](#duże-środowiska)
- [Rozwiązywanie problemów](#rozwiązywanie-problemów)
- [Licencja](#licencja)

## Co sprawdza

| Obszar | Zbierane dane |
|---|---|
| **System** | uptime, oczekujący restart, data ostatniej aktualizacji, obciążenie CPU, użycie RAM i pamięci wirtualnej, zainstalowane role, serwer WSUS, antywirus, źródło czasu i różnica zegara względem stacji, koniec wsparcia systemu, host Hyper-V, na którym działa maszyna |
| **Stabilność** | błędy i zdarzenia krytyczne z dzienników System, Application i Hyper-V, historia restartów i przestojów (kiedy serwer się wyłączył, kiedy wstał, kto i dlaczego go zrestartował), awarie BSOD i pliki zrzutów pamięci, zajętość dysków (także punkty montowania i wolumeny CSV), zdrowie dysków fizycznych i błędy dyskowe, rozmiar dzienników i okres, który obejmują |
| **Bezpieczeństwo** | podstawowy hardening (SMBv1, podpisywanie SMB, NLA, WDigest, poziom LM/NTLM, ochrona LSA, UAC, LLMNR, autologowanie, LAPS, SSL/TLS, PowerShell 2.0, Defender, zapora), zdarzenia bezpieczeństwa (nieudane logowania, blokady, zmiany kont i grup, czyszczenie dzienników, nowe usługi i zadania), polityka audytu, reguły zapory wpuszczające wrażliwe porty, subskrypcje WMI i wykluczenia Defendera, grupy uprzywilejowane, konta lokalne, certyfikaty, udziały, autostart |
| **Usługi, sieć i pliki** | usługi (spoza Microsoft, zatrzymane automatyczne, działające na kontach użytkowników, z niecytowaną ścieżką), zadania harmonogramu spoza `\Microsoft\` z wynikiem ostatniego uruchomienia, karty sieciowe i adresacja, porty nasłuchujące i aktywne połączenia (z procesem i usługą), sesje użytkowników, zawartość wskazanych folderów |
| **Oprogramowanie** | zainstalowane programy, ostatnie aktualizacje (KB) |
| **Kontroler domeny** | SYSVOL/DFSR, replikacja AD, podpisywanie LDAP i channel binding |
| **Hyper-V** | pojemność hosta (vCPU na procesor logiczny, RAM przydzielony maszynom, wolna pamięć), maszyny wirtualne ze stanem, heartbeatem, systemem gościa i adresami IP (z usług integracji), checkpointy, dyski VM i zapas miejsca na ich wzrost, replikacja, ustawienia startu, klaster pracy awaryjnej (węzły, wolumeny CSV, role maszyn, kworum) |

Sekcje kontrolera domeny i Hyper-V pokazują się tylko na serwerach z tą rolą. Hasła wpisane w linię poleceń usług, zadań, autostartu i subskrypcji WMI (np. `-P haslo`, `password=…`) są maskowane już na serwerze i nie trafiają do migawek, raportów ani plików CSV.

## Wymagania

**Stacja, z której uruchamiasz program**

- Windows z Windows PowerShell 5.1 (interfejs korzysta z WPF). Uruchomienie z PowerShell 7 też działa, bo skrypt sam przełącza się wtedy na `powershell.exe`.
- Dostęp do Active Directory, jeśli chcesz pobierać listę serwerów przyciskiem **AD** i sprawdzać konta komputerów w diagnozie niedostępności.

**Serwery**

- Windows Server 2012 R2 lub nowszy. Kolektor działa także w PowerShell 4.0 (2012 R2 bez WMF 5.1).
- Włączony WinRM (domyślnie włączony od Windows Server 2012), port TCP 5985.
- Konto z uprawnieniami administratora lokalnego. Bez nich nie da się m.in. odczytać dziennika Security.

## Uruchomienie

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ServerReview.ps1
```

Opcjonalnie możesz wskazać własny plik z listą serwerów:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ServerReview.ps1 -ServerListFile D:\listy\serwery.txt
```

`-ExecutionPolicy Bypass` dotyczy tylko tego jednego uruchomienia. Jeśli zasady wykonywania skryptów na stacji już na to pozwalają (np. `RemoteSigned`), wystarczy odblokować pobrany plik poleceniem `Unblock-File .\ServerReview.ps1` i uruchomić go jak każdy skrypt.

Program działa w jednym egzemplarzu na folder danych. Drugie uruchomienie z tego samego folderu tylko o tym informuje.

### Skan bez okna (Harmonogram zadań)

Parametr `-Scan` skanuje wszystkie serwery z listy bez otwierania okna, zapisuje migawki, dziennik operacji i dziennik dostępności, a na koniec tworzy raport HTML. Nadaje się do zadania Harmonogramu zadań, np. codziennie rano:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Narzedzia\ServerReview\ServerReview.ps1 -Scan -ReportMode Summary
```

| Parametr | Znaczenie |
|---|---|
| `-Scan` | skan bez okna; PIN nie jest wymagany |
| `-ReportMode Summary` | raport podsumowujący: problemy, niedostępność, Hyper-V i wiersze wymagające uwagi (domyślnie) |
| `-ReportMode Full` | raport pełny ze wszystkimi sekcjami każdego serwera |
| `-NoReport` | bez raportu HTML |

Kod wyjścia: **0** – wszystkie serwery odpowiedziały, **1** – część serwerów bez połączenia lub z przekroczonym limitem czasu, **2** – skan się nie odbył (np. brak listy serwerów albo inny skan bez okna z tego folderu jeszcze trwa). Zadanie musi działać na koncie z uprawnieniami administratora na serwerach. Wyniki skanu bez okna widać po otwarciu programu.

## Pierwsze kroki

1. **Dodaj serwery**, na jeden z trzech sposobów:
   - **AD** dodaje (po potwierdzeniu) włączone konta komputerów z systemem Windows Server (także Hyper-V Server i Azure Stack HCI), które logowały się do domeny w ostatnich 60 dniach. Pomija komputery z Linuksem dołączone do domeny i nazwy wirtualne klastra. Zakres można zawęzić do jednostki organizacyjnej w Ustawieniach.
   - **Plik** wczytuje listę z pliku TXT lub CSV. Bierze pierwszą wartość z każdej linii i pomija puste linie, linie zaczynające się od `#` oraz nagłówki typu `Name` czy `DNSHostName`.
   - Wpisz nazwy w polu pod listą serwerów. Kilka nazw możesz oddzielić przecinkiem, średnikiem lub spacją.

   Duplikaty (np. `SRV01` i `srv01.firma.local`) są pomijane. Lista zapisuje się w `servers.txt` obok skryptu i wczytuje się przy następnym uruchomieniu. Jeśli wskazano własny plik CSV parametrem `-ServerListFile`, nie jest on nadpisywany – zmiany trafiają do `servers.txt`. Maszyny wirtualne z hostów Hyper-V, których brakuje na liście, dodasz w widoku **Hyper-V** (przycisk „Dodaj do listy”).
2. **Wybierz konto** (opcjonalnie). Przycisk z nazwą konta otwiera menu: **Użyj innego konta…** (hasło jest raz sprawdzane w domenie, zanim trafi do serwerów) albo **Wróć do bieżącego konta**. Jeśli trzy kolejne serwery odrzucą podane hasło, a żaden go nie przyjmie, skan zatrzymuje się, żeby nie zablokować konta w domenie.
3. **Ustaw zakres zdarzeń** w polu „Zdarzenia z ostatnich … dni” (1–180) i kliknij **Skanuj wszystkie** (F5). Trwający skan możesz przerwać tym samym przyciskiem albo przyciskiem „Przerwij” na pasku stanu.
4. **Przejrzyj wyniki.** Po starcie programu widoczne są wyniki ostatniego skanu zapisane na dysku – także te z [skanu bez okna](#skan-bez-okna-harmonogram-zadań).

## Interfejs

Okno ma trzy widoki, przełączane przyciskami na górze albo skrótami **Ctrl+1/2/3**: **Wszystkie serwery**, **Hyper-V** i **Szczegóły serwera**. Na górze są też: pole zakresu zdarzeń, przycisk konta, menu **Raport**, ustawienia (⚙, z licznikiem pomijanych sekcji), kłódka blokady i **Skanuj wszystkie**. Na dole okna jest pasek stanu z postępem operacji, przyciskiem **Przerwij** i przyciskiem **Dziennik**. Komunikaty o zakończonych operacjach pojawiają się na chwilę w prawym dolnym rogu.

### Wszystkie serwery

- **Kafelki:** serwery na liście, odpowiadające, bez połączenia, problemy krytyczne, ostrzeżenia oraz hosty Hyper-V i działające maszyny. Kliknięcie kafelka działa jak filtr (np. „Bez połączenia” pokazuje niedostępne serwery i ich problemy łączności, „Hyper-V” otwiera widok Hyper-V).
- **Wykryte problemy:** lista problemów ze wszystkich serwerów z filtrem poziomu i filtrem tekstowym (Ctrl+F). Zaznaczony wiersz pokazuje pełną treść pod tabelą, a dwuklik otwiera serwer w sekcji, której problem dotyczy. Prawy klik: wycisz problem na tym serwerze albo na wszystkich, kopiuj treść, otwórz serwer. Pole **Wyciszone** pokazuje wyciszone problemy. Przycisk **CSV** zapisuje widoczne problemy.
- **Stan serwerów:** jedna linia na każdy serwer z danymi (status, typ HV/VM, system – a dla niedostępnego przyczyna, host Hyper-V, uptime, CPU, RAM, najmniej wolnego miejsca na dysku, dni od aktualizacji, liczba problemów, dostępność z ostatnich 30 dni, ostatni udany skan, czas skanu). Dwuklik otwiera szczegóły serwera. Przycisk **CSV** zapisuje tabelę.

### Hyper-V

Zbiorczy widok wszystkich hostów i maszyn wirtualnych z przeskanowanych hostów:

- **Hosty:** klaster, maszyny działające / wszystkie, vCPU na procesor logiczny, RAM przydzielony maszynom, stare checkpointy, liczba problemów.
- **Maszyny:** host, stan, heartbeat, uptime, vCPU, pamięć (także dynamiczna), generacja i wersja konfiguracji, replikacja, checkpointy, dyski, system gościa, nazwa i adres IP gościa, czy maszyna jest na liście serwerów i jaki jest wynik jej skanu.
- **Filtry:** wszystkie, działające, wyłączone, do sprawdzenia, spoza listy, plus pole tekstowe.
- **Dodaj do listy** dodaje zaznaczone (albo wszystkie widoczne) maszyny Windows spoza listy. Maszyny z Linuksem i repliki Hyper-V Replica są pomijane i wyszarzone.

### Szczegóły serwera

- **Nagłówek:** system i rola, znaczniki (uptime, ostatni start, IP, host Hyper-V albo klaster, aktualizacje, oczekujący restart, antywirus, różnica czasu, dostępność z 30 dni, czas skanu z najwolniejszymi sekcjami), obciążenie CPU i RAM, liczba problemów oraz przyciski **Skanuj ponownie** i **Diagnozuj połączenie** dla tego jednego serwera. Dla serwera bez połączenia znaczniki pokazują przyczynę, od kiedy serwer nie odpowiada i kiedy ostatnio się udało.
- **Lista sekcji:** plakietka przy każdej sekcji pokazuje liczbę pozycji, a jej kolor najpoważniejszy problem w sekcji. Oprócz danych z serwera są tu sekcje **Diagnoza połączenia**, **Historia skanów i dostępność**, **Zmiany od poprzedniego skanu**, **Przestoje** i **Czas zbierania sekcji** (które sekcje wydłużają skan).
- **Tabela sekcji:**
  - pole „Filtruj wiersze” (Ctrl+F) przeszukuje wszystkie kolumny;
  - **CSV** zapisuje widoczne wiersze w kolejności z tabeli (separator `;`, UTF-8);
  - panel pod tabelą pokazuje pełną treść zaznaczonego wiersza i można ją stamtąd skopiować.

Wiersze wymagające uwagi są kolorowane: czerwony oznacza problem krytyczny, żółty ostrzeżenie, a niebieski informację. Wyszarzone są pozycje celowo pomijane (np. maszyny z Linuksem).

### Lista serwerów

- Pole „Szukaj serwera” filtruje listę po nazwie, systemie i hoście Hyper-V. Przyciski nad listą pokazują: wszystkie, z problemami, bez połączenia, hosty Hyper-V, maszyny wirtualne, nieskanowane.
- Można zaznaczyć wiele serwerów (Ctrl/Shift + klik). **Shift+F5** skanuje zaznaczone, a klawisz **Delete** usuwa je z listy.
- Prawy klik otwiera menu: skanuj zaznaczone, diagnozuj połączenie, kopiuj nazwy, połączenie RDP, PowerShell (`Enter-PSSession`), Zarządzanie komputerem, Podgląd zdarzeń, Usługi, udział `C$`, przejście do hosta Hyper-V albo do maszyn hosta, usuń z listy.

### Sortowanie tabel

Wszystkie tabele można sortować kliknięciem w nagłówek kolumny:

- kolejne kliknięcia przełączają sortowanie: **rosnąco → malejąco → kolejność oryginalna**;
- **Shift+klik** dodaje kolejną kolumnę do sortowania;
- liczby porównywane są jak liczby, a wersje i adresy IP naturalnie (`10.0.2` przed `10.0.10`);
- puste pola zawsze trafiają na koniec, a kolumny z poziomem ważności sortują się od najpoważniejszych;
- sortowanie jest zapamiętywane osobno dla każdej tabeli i sekcji, więc zostaje po przełączeniu serwera i przy odświeżaniu w trakcie skanu.

### Skróty klawiszowe

| Skrót | Działanie |
|---|---|
| F5 | skanuj wszystkie serwery |
| Shift+F5 | skanuj zaznaczone serwery |
| Ctrl+1 / Ctrl+2 / Ctrl+3 | widok: wszystkie serwery / Hyper-V / szczegóły serwera |
| Ctrl+F | przejdź do pola filtra w bieżącym widoku |
| Esc | wyczyść pole tekstowe, w którym jest kursor |
| Ctrl+L | pokaż lub ukryj dziennik operacji |
| Ctrl+Shift+L | zablokuj program (gdy ustawiono PIN) |
| Delete | usuń zaznaczone serwery z listy |

## Niedostępne serwery

Gdy serwer nie odpowiada, program nie poprzestaje na komunikacie WinRM. Od razu, ze stacji i w tle, sprawdza:

- **DNS:** czy nazwa się rozwiązuje, na jaki adres, oraz rekord odwrotny (PTR). PTR wskazujący inny komputer oznacza nieaktualny wpis DNS – częstą przyczynę błędów Kerberos.
- **Ping i porty TCP** (domyślnie 5985 WinRM, 5986, 135, 445, 3389), równolegle i z limitem czasu. Port „zamknięty” (host odrzuca połączenie) znaczy, że serwer działa, ale nic na tym porcie nie nasłuchuje. „Brak odpowiedzi” to zapora albo wyłączony serwer.
- **TrustedHosts** na stacji – dla serwerów dodanych po adresie IP.
- **Konto komputera w AD:** czy istnieje, czy jest włączone, kiedy ostatnio logowało się do domeny i kiedy zmieniło hasło (stare hasło konta komputera to typowy objaw zerwanego kanału zabezpieczeń, np. po przywróceniu maszyny z checkpointu), system według AD.
- **Zduplikowany SPN** `HTTP/<serwer>` na innym koncie – przy błędzie Kerberos 0x80090322.
- **Kod błędu WinRM** – rozpoznawany po kodach niezależnych od języka systemu (np. odmowa dostępu, błędne hasło, Kerberos, limit powłok WinRM, przekroczony limit pamięci powłoki).
- **Stan maszyny wirtualnej na hoście Hyper-V**, jeśli serwer jest maszyną z przeskanowanego hosta: wyłączona, zapisana, wstrzymana (zwykle brak miejsca na wolumenie z dyskami), w stanie krytycznym albo działająca, ale z systemem gościa, który nie odpowiada.

Z tych wyników powstaje jedna przyczyna i zalecenie po polsku, np. „Serwer działa, ale WinRM (TCP 5985) jest blokowany – zapora na serwerze albo w sieci” z podpowiedzią, którą regułę zapory włączyć. Pełne wyniki prób są w sekcji **Diagnoza połączenia**, razem z ostatnimi udanymi danymi serwera (kiedy, jaki system, jaki adres). Diagnozę można powtórzyć przyciskiem **Diagnozuj połączenie** albo z menu listy serwerów, także dla wielu serwerów naraz. Na liście serwerów podpis pod nazwą od razu mówi, co się stało: „nie odpowiada”, „zapora blokuje WinRM”, „WinRM nie działa”, „brak w DNS”, „odmowa dostępu”, „błąd Kerberos”, „VM wyłączona na HV01”, „host HV02 nie odpowiada” itp.

Poziom problemu zależy od przyczyny: maszyna wyłączona od ponad 30 dni to informacja (prawdopodobnie wycofana), błąd zbierania danych na działającym serwerze to ostrzeżenie, a serwer, który nie odpowiada, to problem krytyczny.

**Awarie zbiorcze.** Gdy nie odpowiada host Hyper-V, a razem z nim maszyny, które ostatnio na nim działały, program pokazuje jeden problem krytyczny na hoście, a problemy maszyn obniża do ostrzeżeń z dopiskiem „zacznij od hosta”. Gdy nie odpowiada co najmniej 3 i co najmniej 80% znanych serwerów z jednej podsieci /24, pojawia się jeden problem „Sieć” dla całej podsieci. Gdy w pełnym skanie nie odpowiedział żaden serwer, a przyczyny to sieć lub DNS, program podejrzewa problem stacji (VPN, DNS, karta sieciowa) i zgłasza to zamiast setek osobnych awarii.

**Szybki test portu i ponowna próba.** Przed połączeniem WinRM program sprawdza port 5985 (dwie próby po 3 s). Wyłączony serwer zostaje rozpoznany w kilka sekund i nie zajmuje wątku skanu przez pełny limit połączenia. Po skanie serwery z błędem, który może być chwilowy (serwer w trakcie restartu, WinRM jeszcze nie wystartował, chwilowy błąd sieci lub limitu powłok), są raz skanowane ponownie. Błędów DNS, zapory, uprawnień i Kerberos program nie ponawia. Obie funkcje można wyłączyć w Ustawieniach.

**Przerwany skan to nie awaria.** Serwer, którego skan przerwano albo który nie zdążył w limicie czasu, zachowuje poprzednie dane. Przy przekroczeniu limitu pojawia się ostrzeżenie, że pokazane dane pochodzą z wcześniejszego skanu.

Niedostępność jest zapamiętywana: po ponownym uruchomieniu programu serwer nadal jest pokazany jako niedostępny, z przyczyną i datą. Każdy wynik skanu trafia do [dziennika dostępności](#dziennik-operacji-i-dziennik-dostępności), a sekcja **Historia skanów i dostępność** pokazuje historię serwera z ostatnich 3 miesięcy.

## Hyper-V i klastry

- **Powiązanie gościa z maszyną.** Program łączy serwer z listy z maszyną wirtualną na hoście po identyfikatorze maszyny i nazwie hosta odczytanych z usług integracji gościa, a gdy ich brak – po nazwie systemu gościa (KVP) albo nazwie maszyny. Dzięki temu wie, na którym hoście działa serwer, i potrafi wyjaśnić jego niedostępność stanem maszyny.
- **Linux jest pomijany.** Maszyny, których system gościa według hosta nie jest Windows, nie są skanowane ani zgłaszane jako niedostępne. Nie ostrzegamy też o ich heartbeacie.
- **Pojemność hosta.** vCPU działających maszyn na procesor logiczny, RAM przydzielony maszynom i zapas wolnej pamięci hosta (na hoście Hyper-V wysokie zajęcie RAM to normalny stan – liczy się zapas na nowe maszyny i migracje).
- **Klaster.** Stan węzłów, wolumenów CSV, ról maszyn i kworum jest oceniany raz na klaster, a nie na każdym węźle. Gdy przeskanowano wszystkie węzły, program sprawdza, czy klaster przetrwa awarię największego węzła (N+1). Przyrost dysków dynamicznych na wolumenach CSV i udziałach SMB jest sumowany ze wszystkich hostów, które z nich korzystają.
- **Kontrolery domeny.** Ostrzeżenie, gdy wszystkie skanowane kontrolery domeny działają na jednym hoście.
- **Duplikaty.** Ta sama maszyna dodana pod dwiema nazwami (alias DNS, adres IP, nazwa klastra) jest wykrywana.

## Wykrywane problemy

Każdy problem ma jeden z trzech poziomów. Progi podane poniżej to wartości domyślne, które można zmienić w [Ustawieniach](#ustawienia).

**Krytyczny**

- serwer nie odpowiada (z przyczyną z [diagnozy](#niedostępne-serwery)); maszyna wirtualna serwera wstrzymana (Paused) albo w stanie krytycznym na hoście;
- host Hyper-V nie odpowiada razem z co najmniej 2 maszynami z listy, które na nim działały; nie odpowiada większość serwerów jednej podsieci; żaden serwer nie odpowiedział z powodu sieci stacji;
- mniej niż 10% wolnego miejsca na dysku (także punkty montowania i wolumeny CSV);
- nieudane logowania z adresów publicznych, czyli logowanie (RDP/SMB) jest prawdopodobnie dostępne z internetu;
- wyczyszczony dziennik zdarzeń;
- różnica czasu względem stacji co najmniej 300 s (limit Kerberos);
- system po końcu wsparcia Microsoft;
- dysk fizyczny w stanie awarii; co najmniej 2 awarie BSOD w analizowanym okresie;
- krytyczne ustawienia bezpieczeństwa: wyłączona ochrona w czasie rzeczywistym, sygnatury antywirusa starsze niż 7 dni, włączony WDigest, autologowanie z zapisanym hasłem, jawnie włączone SSL 2.0/3.0;
- kontroler domeny: błąd replikacji SYSVOL (DFSR), replikacja AD bez sukcesu od ponad doby, krytyczne zdarzenia replikacji;
- Hyper-V: maszyna wstrzymana (zwykle brak miejsca na wolumenie z dyskami) albo w stanie krytycznym (brak dostępu do plików maszyny);
- klaster: węzeł w stanie Down, wolumen CSV nie Online, rola maszyny w stanie Failed.

**Ostrzeżenie**

- skan serwera przekroczył limit czasu (pokazane są poprzednie dane); serwer odpowiada, ale kolektor zakończył się błędem; maszyna wirtualna serwera wyłączona (do 30 dni) lub zapisana; niedostępny gość niedostępnego hosta Hyper-V;
- mniej niż 20% wolnego miejsca na dysku;
- uptime powyżej 45 dni, oczekujący restart, brak aktualizacji od ponad 45 dni;
- użycie RAM lub pamięci wirtualnej co najmniej 90%, zdarzenia wyczerpania pamięci (na hoście Hyper-V zamiast progu RAM liczy się zapas wolnej pamięci: mniej niż 8 GB);
- zatrzymane usługi automatyczne, niecytowane ścieżki usług, nieudane zadania harmonogramu;
- zdarzenia krytyczne w dziennikach, nieoczekiwane wyłączenia (z odesłaniem do sekcji Przestoje), pojedyncza awaria BSOD, pliki zrzutów pamięci;
- co najmniej 25 nieudanych logowań, utworzenie lub usunięcie konta, dodanie do grupy, włączone konto Gość;
- certyfikaty wygasające w ciągu 30 dni;
- pełny dziennik zdarzeń, dziennik Security obejmujący krótszy okres niż analiza, niepełna polityka audytu;
- zużycie SSD co najmniej 90%, nieskorygowane błędy dysków, błędy dysku i NTFS, co najmniej 10 ponowień lub resetów operacji dyskowych;
- porty wrażliwe otwarte z dowolnego adresu, gdy karta sieciowa jest w profilu Publicznym;
- subskrypcje WMI uruchamiające polecenia lub skrypty (możliwy mechanizm trwałości);
- różnica czasu co najmniej 60 s, kontroler PDC bez zewnętrznego źródła czasu albo biorący czas z hosta Hyper-V;
- ustawienia hardeningu oznaczone jako „Uwaga”, np. wyłączony profil zapory, włączony SMBv1, RDP bez NLA, LM/NTLM poniżej poziomu 3, wyłączony UAC, Print Spooler na kontrolerze domeny, PowerShell 2.0, jawnie włączone TLS 1.0/1.1;
- kontroler domeny: SYSVOL jeszcze na FRS, błędy replikacji z ostatniej doby, ostrzeżenia replikacji, wymuszanie podpisywania LDAP i channel binding wyłączone;
- Hyper-V na hoście: usługa vmms nie działa; vCPU działających maszyn powyżej 6 na procesor logiczny; RAM przydzielony maszynom co najmniej 90% RAM hosta;
- Hyper-V na maszynach: maszyna w stanie zapisanym, działająca maszyna bez odpowiedzi heartbeat (system gościa zawieszony), problemy replikacji, karta sieciowa niepodłączona do przełącznika, maszyna spoza klastra, która nie wystartuje sama po restarcie hosta, wyłączanie maszyny przez „TurnOff” przy zamykaniu hosta, pamięć dynamiczna na maksimum, łańcuch dysków różnicowych dłuższy niż 3, dysk maszyny na dysku systemowym hosta;
- checkpointy starsze niż 7 dni, checkpoint typu Recovery starszy niż doba (pozostałość po kopii zapasowej);
- dyski dynamiczne VM, które mogą urosnąć ponad wolne miejsce na wolumenie – na wolumenach CSV i udziałach SMB liczone łącznie dla wszystkich hostów;
- klaster: węzeł w innym stanie niż Up/Down (np. Paused), rola częściowo online, kworum nie Online, klaster nie przetrwa awarii największego węzła (N+1);
- wszystkie skanowane kontrolery domeny działają na jednym hoście;
- zegar stacji różni się od większości serwerów (wtedy różnice czasu serwerów są liczone względem mediany, zamiast ostrzeżenia na każdym serwerze);
- nowe pozycje od poprzedniego skanu.

**Info**

- zalecenie naprawy dla niedostępnego serwera; maszyna wyłączona od ponad 30 dni (prawdopodobnie wycofana); serwer z Linuksem pominięty;
- podsumowanie błędów w dziennikach, zainstalowane usługi, nowe lub zaktualizowane oprogramowanie z ostatnich 14 dni;
- konta z hasłem bez wygasania, osierocone SID-y w grupach, wygasłe certyfikaty;
- udziały z zapisem dla Wszystkich, pliki wykonywalne w sprawdzanych folderach;
- wyłączone maszyny wirtualne, stara wersja konfiguracji maszyny (Windows Server 2022/2025 jej nie uruchomi), przestoje z ostatnich dni z inicjatorem ostatniego restartu;
- rozłączone sesje, połączenia przychodzące z adresów publicznych, wykluczenia Defendera;
- zbliżający się koniec wsparcia systemu (365 dni);
- skan serwera trwał co najmniej 70% limitu czasu (z trzema najwolniejszymi sekcjami);
- ta sama maszyna na liście pod dwiema nazwami (alias DNS, adres IP, nazwa klastra);
- sekcje, których nie udało się zebrać na danym serwerze.

## Wyciszanie problemów

Przy kilkuset serwerach część problemów to świadome wyjątki (np. stara aplikacja wymagająca TLS 1.0). Takie problemy można wyciszyć:

- prawy klik na problemie → **Wycisz na serwerze …** albo **Wycisz na wszystkich serwerach**;
- wyciszony problem nie liczy się do kafelków, liczników na liście serwerów ani raportu podsumowującego, a w szczegółach serwera jest pokazany na końcu, wyszarzony;
- pole **Wyciszone** nad listą problemów pokazuje wyciszone problemy, a prawy klik → **Przywróć** usuwa wyciszenie;
- pełna lista reguł (serwer, treść, kiedy i kto wyciszył) jest w **Ustawienia → Wyciszone problemy…**.

Reguła działa także w kolejnych skanach, bo wartości zmienne w treści problemu (procenty, liczby dni, daty, liczniki) są przy dopasowaniu pomijane. Nazwy maszyn, numery zdarzeń, portów i aktualizacji KB są brane pod uwagę, więc wyciszenie problemu jednej maszyny nie wycisza innych. Reguły zapisują się w `settings.json`.

## Porównanie z poprzednim skanem

Każdy skan zapisuje migawkę danych serwera (skompresowany JSON). Kolejny skan porównuje się z poprzednim i w sekcji **Zmiany od poprzedniego skanu** pokazuje nowe oraz usunięte pozycje w obszarach:

- usługi spoza Microsoft;
- zadania harmonogramu;
- porty nasłuchujące (porty dynamiczne RPC 49152+ porównywane są po procesie i usłudze, bo zmieniają się po każdym restarcie);
- grupy uprzywilejowane i konta lokalne;
- udziały;
- autostart;
- oprogramowanie;
- subskrypcje WMI i wykluczenia AV;
- reguły zapory.

Nowe pozycje są zgłaszane jako ostrzeżenia, a w przypadku oprogramowania jako informacja. Sekcja pominięta albo niezebrana w którymkolwiek z porównywanych skanów nie jest porównywana (inaczej cała jej zawartość wyglądałaby na „nową”). Pierwszy skan po aktualizacji programu do nowej wersji kolektora też nie jest porównywany – zmiany są pokazywane od kolejnego skanu.

## Raport HTML

Menu **Raport** ma dwie wersje raportu:

- **Podsumowanie** – kafelki, wszystkie aktywne problemy, niedostępne serwery z przyczyną, hosty i maszyny Hyper-V wymagające uwagi oraz, dla każdego serwera, tylko wiersze oznaczone jako problem. Nadaje się do przesłania dalej.
- **Pełny** – dodatkowo wszystkie sekcje każdego serwera, wczytywane kolejno z migawek (do 500 wierszy na sekcję). Przy ponad 60 serwerach program pyta o potwierdzenie, bo plik może mieć kilkadziesiąt MB.

Menu ma też pozycję **Otwórz folder raportów**. Raport zapisuje się w folderze `Reports` jako `Przeglad_serwerow_RRRRMMDD_GGMM.html` (wersja pełna z dopiskiem `_pelny`) i otwiera w przeglądarce. Wygląd dopasowuje się do jasnego lub ciemnego motywu systemu, a raport nadaje się do druku. Raport powstaje strumieniowo, bez wczytywania wszystkich danych do pamięci naraz.

## Dziennik operacji i dziennik dostępności

**Dziennik operacji** (przycisk **Dziennik** na pasku stanu albo **Ctrl+L**) to panel na dole okna z przebiegiem pracy programu: start i koniec skanów, wynik każdego serwera (z czasem skanu i najwolniejszymi sekcjami), przyczyny niedostępności, ponowne próby, zmiany ustawień, wyciszenia, błędy. Filtr pokazuje wszystko, tylko ostrzeżenia i błędy albo tylko błędy. Przy ukrytym panelu licznik na przycisku pokazuje liczbę nowych ostrzeżeń i błędów. Wpisy można skopiować, a przyciskami obok otworzyć plik dziennika albo folder `Logs`. Dziennik zapisuje się do pliku `Logs\ServerReview_RRRRMMDD.log` (jeden plik na dzień).

**Dziennik dostępności** to plik `Logs\Availability_RRRRMM.csv` (jeden na miesiąc, separator `;`, otwiera się w Excelu). Każdy wynik skanu każdego serwera to jeden wiersz:

| Kolumna | Zawartość |
|---|---|
| Czas | data i godzina wyniku |
| Serwer | nazwa z listy |
| Status | `OK`, `Brak połączenia`, `Błąd zbierania danych` albo `Limit czasu` |
| CzasSkanu | czas skanu serwera [s] |
| Krytyczne, Ostrzezenia | liczba problemów po udanym skanie |
| Rodzaj | rodzaj niedostępności, np. `Offline`, `Firewall`, `WinRM`, `Dns`, `Auth`, `Kerberos` |
| Szczegoly | przyczyna po polsku |

Na tej podstawie tabela stanu serwerów pokazuje dostępność z ostatnich 30 dni i datę ostatniego udanego skanu, a szczegóły serwera – historię skanów. Obydwa dzienniki są przechowywane przez 90 dni (ustawienie „Przechowuj dziennik operacji i dostępności”).

## Blokada programu (PIN)

Blokada chroni otwarty program przed osobą postronną przy odblokowanej stacji (np. gdy administrator odejdzie od biurka z otwartym programem i poświadczeniami do serwerów).

- **Ustawienie PIN-u:** **Ustawienia → Ustaw PIN…** (4–8 cyfr). Zmiana i usunięcie PIN-u wymagają podania obecnego. W `settings.json` zapisuje się tylko sól i skrót PBKDF2, nigdy sam PIN.
- **Blokowanie:** przycisk z kłódką na górze okna, **Ctrl+Shift+L** albo automatycznie po bezczynności (domyślnie 10 minut, `0` wyłącza). Przy uruchomieniu programu PIN jest wymagany, jeśli zaznaczono „Wymagaj PIN-u przy uruchomieniu programu”.
- **W czasie blokady** zawartość okien programu jest ukryta, ale skan w tle trwa dalej. PIN wpisuje się klawiaturą (także numeryczną) albo przyciskami na ekranie.
- **Błędny PIN:** na ekranie blokady po 5 nieudanych próbach wpisywanie jest wstrzymane na 30 sekund (bez limitu cykli). Przy uruchomieniu programu 5 błędnych prób kończy program bez otwierania okna.
- **Zamknięcie bez PIN-u:** przycisk **Zakończ awaryjnie** na ekranie blokady, potwierdzony drugim kliknięciem w ciągu 10 sekund. Program się wtedy zamyka, a dane zostają na dysku.

Bez ustawionego PIN-u blokada jest wyłączona, a przycisk z kłódką ukryty. Skan bez okna (`-Scan`) nie wymaga PIN-u. Blokada nie chroni przed administratorem komputera – skrypt i pliki danych to zwykłe pliki.

## Ustawienia

Przycisk ⚙ otwiera okno ustawień. Zmiany zapisują się w pliku `settings.json` obok skryptu i nadpisują wartości domyślne z bloku `$Config` na początku skryptu. Przycisk „Przywróć domyślne” wraca do tych wartości, a „Folder danych” otwiera folder programu. Po zapisaniu zmienionych progów wyniki są analizowane ponownie, bez nowego skanu – od razu albo, jeśli trwa skan, zaraz po jego zakończeniu.

**Zakres skanu.** Odznaczone sekcje nie są zbierane ani porównywane, co skraca skan. Liczba pomijanych sekcji wyświetla się przy zębatce. Sekcja **Czas zbierania sekcji** w szczegółach serwera pokazuje, które sekcje trwają najdłużej.

**Skan**

| Ustawienie | Domyślnie |
|---|---|
| Zakres zdarzeń [dni] | 7 |
| Limit pobieranych zdarzeń (osobno dla każdego dziennika i rodzaju) | 3000 |
| Uwzględniaj ostrzeżenia z dzienników System/Application (dużo szumu) | nie |
| Ile serwerów skanować równolegle | 25 |
| Limit czasu jednego serwera [s] | 300 |
| Limit nawiązania połączenia WinRM [s] | 30 |
| Limit czasu całego skanu [s] | 3600 |
| Szybki test portu WinRM 5985 przed skanem (wyłączone serwery są rozpoznawane w kilka sekund) | tak |
| Po skanie ponów raz serwery z błędem, który może być chwilowy (restart, przeciążony WinRM) | tak |

**Progi: system i dyski**

| Ustawienie | Domyślnie |
|---|---|
| Dysk: ostrzeżenie poniżej [% wolnego] | 20 |
| Dysk: krytyczne poniżej [% wolnego] | 10 |
| RAM: ostrzeżenie od [%] | 90 |
| Pamięć wirtualna (commit): ostrzeżenie od [%] | 90 |
| Uptime: ostrzeżenie powyżej [dni] | 45 |
| Aktualizacje: ostrzeżenie po [dniach] | 45 |
| Koniec wsparcia systemu: uprzedzaj [dni] wcześniej | 365 |
| Różnica czasu: ostrzeżenie od [s] | 60 |
| Różnica czasu: krytyczne od [s] | 300 |
| Zużycie SSD: ostrzeżenie od [%] | 90 |
| Ponowienia/resety I/O dysku: ostrzeżenie od [liczba] | 10 |
| BSOD: krytyczne od [liczba w okresie] | 2 |

**Progi: bezpieczeństwo**

| Ustawienie | Domyślnie |
|---|---|
| Certyfikaty: ostrzeżenie na [dni] przed wygaśnięciem | 30 |
| Nieudane logowania: ostrzeżenie od [liczba] | 25 |
| Nowe oprogramowanie: z ostatnich [dni] | 14 |

**Hyper-V**

| Ustawienie | Domyślnie |
|---|---|
| Checkpoint: ostrzeżenie po [dniach] | 7 |
| Host: RAM przydzielony działającym maszynom – ostrzeżenie od [% RAM hosta] | 90 |
| Host: vCPU działających maszyn na procesor logiczny – ostrzeżenie powyżej | 6 |
| Host: ostrzeżenie, gdy wolnej pamięci zostaje mniej niż [GB] (zamiast progu RAM %) | 8 |
| Maszyna wyłączona dłużej niż [dni] = prawdopodobnie wycofana (informacja zamiast ostrzeżenia) | 30 |

**Diagnostyka i Active Directory**

| Ustawienie | Domyślnie |
|---|---|
| Diagnoza niedostępności: limit próby DNS/ping/portu [ms] | 2000 |
| Diagnoza niedostępności: sprawdzane porty TCP (jeden na linię) | 5985, 5986, 135, 445, 3389 |
| „Pobierz z AD”: jednostka organizacyjna (DN), puste = cała domena | (puste – cała domena) |
| „Pobierz z AD”: pomijaj konta nieaktywne dłużej niż [dni] | 60 |

**Dane, dziennik i blokada**

| Ustawienie | Domyślnie |
|---|---|
| Ile migawek (skanów) każdego serwera przechowywać | 30 |
| Kompresuj migawki (.json.gz – ok. 10x mniej miejsca) | tak |
| Przechowuj dziennik operacji i dostępności [dni] | 90 |
| Blokada programu po bezczynności [min] (0 = wyłączona; wymaga PIN-u) | 10 |

**Listy**

| Ustawienie | Domyślnie |
|---|---|
| Foldery sprawdzane na serwerach (jeden na linię, zmienne środowiskowe dozwolone) | `C:\Temp`, `C:\Windows\Temp`, `C:\Users\Public\Downloads`, `C:\Install`, `C:\Scripts` |
| Usługi automatyczne, których zatrzymanie jest OK (jedna na linię, wildcardy `*`) | lista usług systemowych (obsługuje wildcardy `*`) |
| Porty wrażliwe dla sekcji Ekspozycja (jeden na linię) | 21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986 |
| Subskrypcje WMI traktowane jako systemowe (jedna na linię) | subskrypcje obecne w czystym systemie |

Pole „Zdarzenia z ostatnich … dni” w głównym oknie zmienia zakres tylko dla bieżącego skanu.

Wymagane podkategorie polityki audytu (`AuditRequired`) i daty końca wsparcia systemów (`OsSupportEnd`) nie mają pól w oknie ustawień. Zmienia się je bezpośrednio w bloku `$Config` w skrypcie.

## Pliki programu

Program trzyma wszystkie dane w folderze, w którym leży skrypt:

```text
ServerReview.ps1
servers.txt                                       lista serwerów
settings.json                                     ustawienia, wyciszenia, stan okna, skrót PIN-u
Snapshots\RRRRMMDD_GGMMSS\<serwer>.json.gz        migawki skanów (skompresowane)
Snapshots\RRRRMMDD_GGMMSS\<serwer>.offline.json   nieudana próba: błąd i wynik diagnozy
Reports\Przeglad_serwerow_RRRRMMDD_GGMM.html      raporty HTML
Logs\ServerReview_RRRRMMDD.log                    dziennik operacji
Logs\Availability_RRRRMM.csv                      dziennik dostępności
```

Jeśli skrypt uruchomiono bez pliku (np. wklejony do konsoli), zamiast folderu skryptu używany jest `%USERPROFILE%\Documents\ServerReview`. Jeśli folder skryptu jest tylko do odczytu (np. udział sieciowy), dane trafiają do `%LOCALAPPDATA%\ServerReview`, a lista serwerów i ustawienia są tam kopiowane przy pierwszym uruchomieniu.

Dla każdego serwera przechowywanych jest domyślnie 30 ostatnich migawek (znaczniki nieudanych prób też się liczą). Starsze są usuwane po skanie, ale ostatnia udana migawka zostaje zawsze – długo niedostępny serwer nie traci ostatnich znanych danych. Puste foldery starych skanów znikają. Migawki z poprzednich wersji programu (`.json`) są nadal odczytywane. Migawki i ustawienia zapisują się przez plik tymczasowy, więc przerwany zapis nie psuje danych.

## Duże środowiska

Program jest przygotowany na kilkaset serwerów i kilkadziesiąt hostów Hyper-V:

- każdy serwer to osobne zadanie w puli wątków, z własnym limitem czasu liczonym od chwili, gdy jego skan faktycznie ruszył – serwery z końca kolejki nie są oznaczane jako niedostępne tylko dlatego, że czekały;
- hosty Hyper-V i serwery, które ostatnio skanowały się najdłużej, idą na początek kolejki, żeby nie wydłużać końcówki skanu;
- odbiór wyników, zapis migawek, parsowanie i diagnoza niedostępności odbywają się w tle; okno odświeża się co ok. 1,5 s i pozostaje responsywne;
- migawki są kompresowane (ok. 10 razy mniej miejsca), a w pamięci trzymane są tylko dane potrzebne do list i raportu podsumowującego – pełne dane serwera wczytują się z dysku przy otwarciu jego szczegółów;
- wyniki z dysku wczytują się przy starcie równolegle, a indeks migawek powstaje w jednym przejściu po folderach;
- liczba równoległych połączeń, limity czasu i liczba przechowywanych migawek są w Ustawieniach.

Przy ok. 400 serwerach rozsądne wartości to 25–50 równoległych skanów i limit jednego serwera 300 s. Jeśli serwery z dużymi dziennikami zdarzeń skanują się długo, sekcja **Czas zbierania sekcji** pokaże, co warto wyłączyć albo ograniczyć.

## Rozwiązywanie problemów

- **Brak połączenia z serwerem.** Otwórz sekcję **Diagnoza połączenia** – przyczyna i zalecenie są tam wypisane. Najczęstsze przypadki:
  - *Serwer nie odpowiada w sieci* – wyłączony, odłączony albo całkowicie odfiltrowany; dla maszyny wirtualnej sprawdź stan na hoście.
  - *Port 5985 zamknięty* – usługa WinRM zatrzymana albo brak listenera: `Enable-PSRemoting -Force` na serwerze.
  - *Port 5985 blokowany* – reguła zapory „Windows Remote Management (HTTP-In)” wyłączona albo ograniczona do podsieci lokalnej (np. karta sieciowa w profilu Publicznym), albo zapora sieciowa między stacją a serwerem.
  - *Kerberos 0x80090322* – zduplikowany SPN `HTTP/<serwer>`, alias DNS albo nieaktualny rekord DNS; diagnoza pokazuje konto, na którym jest SPN.
  - *Odmowa dostępu* – konto nie jest administratorem lokalnym serwera.
- **Serwer dodany po adresie IP.** WinRM wymaga wtedy wpisu w TrustedHosts na stacji i podania konta przyciskiem z nazwą konta:

  ```powershell
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value 10.0.0.5 -Concatenate
  ```

- **„Przekroczono limit czasu jednego serwera”.** Zwiększ limit w Ustawieniach albo odznacz najwolniejsze sekcje (sekcja **Czas zbierania sekcji** pokazuje, które to są). Do czasu następnego udanego skanu widoczne są poprzednie dane serwera.
- **„Kolektor przerwał pracę” / „kolektor nie kompiluje się”.** Serwer odpowiada, ale skrypt zbierający dane zakończył się błędem. Treść błędu (z numerem linii i wersją PowerShell serwera) jest w diagnozie i w dzienniku operacji.
- **„Proces WinRM przerwał pracę”.** Najczęściej limit pamięci powłoki WinRM na serwerze: `winrm set winrm/config/winrs @{MaxMemoryPerShellMB="2048"}` albo odznacz duże sekcje.
- **Puste zdarzenia bezpieczeństwa.** Konto musi mieć uprawnienia administratora na serwerze. Sekcja **Polityka audytu** pokazuje, których zdarzeń system w ogóle nie rejestruje.
- **Informacja „Nie udało się zebrać: …”.** Jedna sekcja nie zadziałała na danym serwerze, np. brak modułu w starszym systemie. Pozostałe dane są kompletne.
- **Coś poszło nie tak.** Zajrzyj do dziennika operacji (Ctrl+L) – błędy programu i serwerów są tam opisane, także w pliku `Logs\ServerReview_RRRRMMDD.log`.
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
