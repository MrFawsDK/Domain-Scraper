# Domain Scraper

A Python tool for finding short available domains, mainly made for `.dk` domains.

The scanner checks 2-3 character domain combinations using DNS and then confirms possible available domains using Punktum.dk WHOIS.

Progress is saved in a local SQLite database, so the scanner can be stopped and continued later without starting over.

## Features

* Fast asynchronous DNS scanning
* Direct queries to authoritative `.dk` nameservers
* WHOIS confirmation through Punktum.dk
* Punktum DAS support for registrars
* Saves scan progress using SQLite
* Resume previous scans
* Checks better looking domains first
* Supports custom character sets
* Supports Danish characters such as `æ`, `ø` and `å`
* Regex filtering
* Watch mode for checking domains again automatically
* Discord and Slack webhook notifications
* Supports multiple TLDs
* No external Python dependencies

## Requirements

* Python 3.10+
* UDP port 53 for DNS
* TCP port 43 for WHOIS

## Setup

Clone the repository:

```bash
git clone https://github.com/MrFawsDK/domain-scraper.git
cd domain-scraper
```

Run the scanner:

```bash
python domain_scraper.py
```

Show all available options:

```bash
python domain_scraper.py --help
```

## Usage

Scan all 2-3 character `.dk` domains:

```bash
python domain_scraper.py
```

Only scan 3 letter domains:

```bash
python domain_scraper.py --charset letters --lengths 3
```

Include Danish characters:

```bash
python domain_scraper.py --charset dk
```

Only scan domains matching a pattern:

```bash
python domain_scraper.py --regex "k.."
```

Only confirm the 200 best candidates:

```bash
python domain_scraper.py --limit 200
```

Skip WHOIS confirmation and only use DNS:

```bash
python domain_scraper.py --no-confirm
```

List all known available domains:

```bash
python domain_scraper.py --list
```

Watch for available domains every 30 minutes:

```bash
python domain_scraper.py --charset letters --watch 30
```

Watch and send newly available domains to a Discord webhook:

```bash
python domain_scraper.py --charset letters --watch 30 --webhook "https://discord.com/api/webhooks/..."
```

Scan multiple TLDs:

```bash
python domain_scraper.py --tlds dk,io,se
```

## Options

| Option             | Default                 | Description                                      |
| ------------------ | ----------------------- | ------------------------------------------------ |
| `--tlds`           | `dk`                    | Comma separated list of TLDs                     |
| `--lengths`        | `2,3`                   | Domain lengths to scan                           |
| `--charset`        | `all`                   | Character set to use                             |
| `--regex`          | -                       | Only scan domains matching the regex             |
| `--limit`          | -                       | Only confirm the first N candidates              |
| `--concurrency`    | `256`                   | Concurrent DNS lookups                           |
| `--dns-rate`       | `1000`                  | Maximum DNS requests per second                  |
| `--whois-interval` | `1.05`                  | Delay between WHOIS requests                     |
| `--max-age`        | `24`                    | Hours before a confirmed result is checked again |
| `--no-confirm`     | -                       | Skip WHOIS confirmation                          |
| `--watch MIN`      | -                       | Repeat the scan every MIN minutes                |
| `--webhook URL`    | -                       | Discord or Slack webhook for notifications       |
| `--db`             | `domains.db`            | SQLite database file                             |
| `-o`, `--output`   | `available_domains.txt` | File where available domains are saved           |
| `--list`           | -                       | List known available domains and exit            |
| `-v`, `--verbose`  | -                       | Also show registered domains                     |

## How it works

The scanner uses two steps to check if a domain is available.

### DNS

Domains are first checked directly against the authoritative nameservers for the TLD.

For `.dk`, the scanner queries the `.nic.dk` nameservers directly instead of using a normal DNS resolver.

If the domain exists in DNS, it can be marked as registered and skipped.

If DNS returns `NXDOMAIN`, the domain is added as a possible available domain.

DNS alone is not enough to know if a domain is actually available. A registered domain can exist without active nameservers, for example if it is suspended or still being configured.

Because of this, all DNS candidates are confirmed using WHOIS.

```text
Generated domains
      |
      v
     DNS
      |
      +-- Domain exists -> Registered
      |
      +-- NXDOMAIN -> Candidate
                         |
                         v
                       WHOIS
                         |
                         +-- Registered
                         |
                         +-- Available
```

### WHOIS

Candidates found through DNS are checked using Punktum.dk WHOIS.

Punktum limits how quickly WHOIS can be queried, so the scanner waits between requests.

By default:

```text
~1.05 seconds between WHOIS requests
```

If the server starts returning rate limit errors, the scanner automatically slows down and continues.

This makes the DNS part very fast, while WHOIS is used only for domains that actually need to be confirmed.

## Punktum DAS

If you have access to Punktum's Domain Availability Service, the scanner can use DAS instead of normal WHOIS.

Set your credentials:

```bash
export PUNKTUM_DAS_USER="DAS-1234"
export PUNKTUM_DAS_PASSWORD="..."
```

Then run the scanner normally:

```bash
python domain_scraper.py
```

DAS is automatically used for `.dk` domains when credentials are available.

Unlike the public WHOIS service, DAS allows candidates to be checked in parallel. This makes larger scans much faster.

## Database

Everything is stored in:

```text
domains.db
```

This includes the domain, DNS result, availability status and when it was last checked.

The database contains:

```text
domain
ascii
dns
status
checked_at
first_free
```

Confirmed results are reused for the amount of time set with `--max-age`.

The default is:

```text
24 hours
```

This also means the scanner can be stopped with `Ctrl+C` and continued later without losing progress.

You can list all known available domains with:

```bash
python domain_scraper.py --list
```

Or query the database directly:

```bash
sqlite3 domains.db "SELECT domain FROM domains WHERE status='free' ORDER BY domain"
```

## Example

A scan of all 3 letter `.dk` domains can look like this:

```text
[14:02:11] Scanning 17576 domains

.dk: 6 authoritative nameservers

DNS 17576/17576  (786/s)  candidates: 4851

DNS: 4851 candidates, 0 errors, 4851 need confirmation

WHOIS ~1.1s/lookup, est. 85 min
Ctrl+C anytime, progress is saved

[1/4851] acy.dk                   AVAILABLE
[2/4851] ahy.dk                   AVAILABLE
...
```

## Performance

| Scan           | Domains |     DNS | Candidates |      WHOIS |
| -------------- | ------: | ------: | ---------: | ---------: |
| 2 characters   |   1,296 |  ~2 sec |         ~1 |     ~1 sec |
| 3 letters      |  17,576 | ~25 sec |     ~4,850 | ~1.5 hours |
| 2-3 characters | ~49,000 |  ~1 min |    ~30,000 |   ~9 hours |

These numbers were measured in October 2026.

The amount of available domains changes over time, so the number of candidates and total WHOIS time will also change.

For finding normal looking short domains, a good place to start is:

```bash
python domain_scraper.py --charset letters --lengths 3
```

You can also limit the amount of candidates that get confirmed:

```bash
python domain_scraper.py --charset letters --lengths 3 --limit 200
```

The scanner checks the better looking domains first, so using `--limit` can be useful if you only want to find a few good domains.

## Output

Newly found available domains are saved to:

```text
available_domains.txt
```

The full scan state is stored in:

```text
domains.db
```

You can stop the scanner at any time using `Ctrl+C`.

Run the same command again later and it will continue using the saved results.

## Domain Registration

The scanner only checks if domains are available. It does not register or buy them.

Domain availability can change at any time, so always check the domain again before registering it.

For `.dk` domains, they can be registered through a `.dk` registrar.

## Responsible Use

Do not set `--whois-interval` too low.

Punktum.dk rate limits WHOIS requests and excessive requests can result in temporary blocking.

Keep `--dns-rate` at a reasonable level. Authoritative DNS servers are shared infrastructure.

WHOIS information should also not be used for marketing or other purposes that violate Punktum's terms.

Finding an available domain does not automatically mean you have the right to use it. Existing trademarks and domain name rules still apply.

## License

MIT
