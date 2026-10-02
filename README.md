# domain-scraper 🇩🇰

Find **ledige korte domæner** (2–3 tegn) — primært `.dk` — så du kan købe dem før alle andre.

Scanneren gennemgår alle ~49.000 kombinationer af 2–3 tegn under `.dk` på under et minut via DNS og bekræfter derefter kandidaterne én for én hos Punktum dk (WHOIS). De mest attraktive navne tjekkes først. Al fremdrift gemmes i en lokal database, så scanningen kan afbrydes og genoptages når som helst.

```
[14:02:11] Scanner 17576 domæner
  .dk: 6 autoritative navneservere
  DNS 17576/17576  (786/s)  kandidater: 4851
  DNS: 4851 kandidater, 0 fejl, 4851 skal bekræftes
  WHOIS ~1.1s/opslag, est. 85 min (afbryd når som helst - fremskridt gemmes)
  [1/4851] acy.dk                   LEDIG
  [2/4851] ahy.dk                   LEDIG
  ...
```

## Funktioner

- ⚡ **Hurtig DNS-scanning**: asynkron rå UDP direkte mod TLD'ens autoritative navneservere (`*.nic.dk`). Der er ingen cache og ingen mellemled, og svarene er i realtid.
- ✅ **Bekræftelse**: kandidater tjekkes via WHOIS (eller Punktum DAS, hvis du er registrator), så du ikke får falske positive.
- 🧠 **Smart rækkefølge**: korte, udtalbare navne med kun bogstaver tjekkes først (`ced.dk` før `c-9.dk`).
- 💾 **Genoptagelse**: resultater gemmes i SQLite. Næste kørsel springer domæner over, der er tjekket inden for de sidste 24 timer.
- 🔔 **Overvågning**: `--watch` scanner igen med faste mellemrum og sender besked (fil og/eller Discord/Slack-webhook), når et domæne bliver ledigt.
- 🇩🇰 **Danske tegn**: `--charset dk` inkluderer `æ ø å ä ö ü é` (IDN/punycode håndteres automatisk).
- 📦 **Ingen afhængigheder**: kun Pythons standardbibliotek.

## Krav

- Python **3.10+**
- Udgående UDP port 53 (DNS) og TCP port 43 (WHOIS)

## Installation

```bash
git clone https://github.com/<dit-brugernavn>/domain-scraper.git
cd domain-scraper
python domain_scraper.py --help
```

## Brug

```bash
# Alle 2-3 tegns .dk-domæner (a-z, 0-9, bindestreg)
python domain_scraper.py

# Kun 3 bogstaver (ingen tal) - det mest interessante sæt
python domain_scraper.py --charset letters --lengths 3

# Inkl. æ, ø, å osv.
python domain_scraper.py --charset dk

# Kun navne der matcher et mønster, fx starter med "k"
python domain_scraper.py --regex "k.."

# Bekræft kun de 200 bedste kandidater
python domain_scraper.py --limit 200

# Hurtigt overblik kun via DNS (ingen WHOIS - kan indeholde falske positive)
python domain_scraper.py --no-confirm

# Vis alle kendte ledige domæner fra databasen
python domain_scraper.py --list

# Overvåg hvert 30. minut og få besked i Discord
python domain_scraper.py --charset letters --watch 30 --webhook "https://discord.com/api/webhooks/..."

# Andre endelser
python domain_scraper.py --tlds dk,io,se
```

### Alle indstillinger

| Flag | Standard | Beskrivelse |
|---|---|---|
| `--tlds` | `dk` | Kommasepareret liste af endelser |
| `--lengths` | `2,3` | Længder der scannes |
| `--charset` | `all` | `letters`, `digits`, `alnum`, `all` (+ `-`), `dk` (+ `æøåäöüé`) |
| `--regex` | – | Kun navne der matcher (fuldt match) |
| `--limit` | – | Bekræft kun de N bedste kandidater |
| `--concurrency` | `256` | Samtidige DNS-opslag |
| `--dns-rate` | `1000` | Max DNS-opslag pr. sekund |
| `--whois-interval` | `1.05` | Sekunder mellem WHOIS-opslag |
| `--max-age` | `24` | Timer før et bekræftet resultat tjekkes igen |
| `--no-confirm` | – | Spring WHOIS over |
| `--watch MIN` | – | Gentag hvert MIN minut |
| `--webhook URL` | – | Discord/Slack-webhook til notifikationer |
| `--db` | `domains.db` | SQLite-fil med tilstand |
| `-o`, `--output` | `ledige_domaener.txt` | Nye ledige domæner tilføjes her |
| `--list` | – | Vis kendte ledige og stop |
| `-v`, `--verbose` | – | Vis også optagne domæner |

## Sådan virker det

```
 generér navne ──► sortér efter værdi ──► DNS mod *.nic.dk ──► WHOIS / DAS ──► SQLite + notifikation
   (~49k)                                   NXDOMAIN = kandidat    "No entries found" = LEDIG
```

1. **DNS (trin 1)**: For hvert navn spørges TLD'ens egne navneservere direkte. Et *delegeret* domæne er altid registreret, så det udelukkes med det samme. Svarer serveren `NXDOMAIN`, er domænet en *kandidat*.
   Navneserverne bruger Response Rate Limiting og svarer med tomme/afkortede pakker, hvis man spørger for hurtigt. Scanneren genkender dem og prøver igen, så resultatet er korrekt selv ved høj hastighed.
2. **Bekræftelse (trin 2)**: Et domæne kan være registreret uden navneservere (fx suspenderet eller under oprettelse). Derfor tjekkes hver kandidat hos registret:
   - **WHOIS** (`whois.punktum.dk`): offentligt og gratis, men begrænset til ca. 1 opslag pr. sekund. En adaptiv rate-limiter sænker farten automatisk, hvis serveren melder "Too many requests", og øger den igen bagefter.
   - **DAS** (Punktum Domain Availability Service): uden rate-limit, men kræver registrator-adgang. Sæt miljøvariablerne nedenfor, så bruges den automatisk for `.dk`.
3. **Tilstand**: alt gemmes i `domains.db`. Optagne domæner (delegeret i DNS) tjekkes ved hver kørsel, fordi det er gratis. WHOIS-resultater genbruges i `--max-age` timer.

### Punktum DAS (valgfrit, kun registratorer)

```bash
export PUNKTUM_DAS_USER="DAS-1234"
export PUNKTUM_DAS_PASSWORD="..."
python domain_scraper.py
```

Med DAS bekræftes kandidater parallelt i stedet for ~1 pr. sekund. Se [DAS-specifikationen](https://github.com/Punktum-dk/das-service-specification).

## Hvor lang tid tager det?

| Scanning | Domæner | DNS | Kandidater* | WHOIS-bekræftelse* |
|---|---|---|---|---|
| 2 tegn, `all` | 1.296 | ~2 s | ~1 | ~1 s |
| 3 bogstaver (`letters`) | 17.576 | ~25 s | ~4.850 | ~1,5 t |
| 2–3 tegn, `all` | ~49.000 | ~1 min | ~30.000 | ~9 t |

\* Målt oktober 2026. Tallene ændrer sig, når domæner registreres og slettes.

Tip: Start med `--charset letters --lengths 3` og brug `--limit` for at få de bedste navne bekræftet først. Kør resten i baggrunden. Afbryd med `Ctrl+C`, og fortsæt senere med samme kommando.

## Resultater

- `ledige_domaener.txt`: nye ledige domæner tilføjes her, efterhånden som de bliver fundet
- `domains.db`: SQLite med alle domæner (`domain`, `ascii`, `dns`, `status`, `checked_at`, `first_free`)

```bash
sqlite3 domains.db "SELECT domain FROM domains WHERE status='free' ORDER BY domain"
```

## Køb af domæner

Scriptet *finder* ledige domæner, men køber dem ikke. Registrér dem hos en dansk registrator eller via [punktum.dk](https://www.punktum.dk). Tjek altid tilgængeligheden igen lige før køb.

## Ansvarlig brug

- Punktum logger WHOIS-forespørgsler og kan blokere misbrug. Sæt ikke `--whois-interval` under ~1 sekund.
- WHOIS-data må ifølge Punktums vilkår ikke bruges til markedsføring.
- Hold `--dns-rate` på et fornuftigt niveau. Navneserverne er fælles infrastruktur.
- Spekulation i domæner, der krænker andres varemærker, kan føre til at du mister domænet via [Klagenævnet for Domænenavne](https://www.domaeneklager.dk).

## Licens

MIT
