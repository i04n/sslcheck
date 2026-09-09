# sslcheck

Single-file, zero-dependency SSL/TLS certificate expiry monitor.

```bash
sslcheck -d example.com
```

```
  sslcheck 5 domains · port 443 · threshold 30d

  ● old.example.com    expired    2015-04-12  4168d ago
  ● vpn.example.com    untrusted  2028-09-07  729d left  self-signed certificate
  ● shop.example.com   expiring   2026-09-18  9d left
  ● example.com        valid      2026-10-27  48d left
  ● gone.example.com   error                             [Errno -2] Name or service not known

  1 valid · 1 expiring · 1 untrusted · 1 expired · 1 error
  ✗ 3 domains need attention
  Done in 1.3s
```

## Install

One file, Python stdlib only.

```bash
curl -O https://raw.githubusercontent.com/i04n/sslcheck/main/sslcheck.py
chmod +x sslcheck.py
sudo mv sslcheck.py /usr/local/bin/sslcheck
```

Requires Python 3.6+. Nothing else.

## Usage

```bash
# one or more domains
sslcheck -d example.com google.com github.com

# from file (one per line)
sslcheck -f domains.txt

# custom warning threshold (days)
sslcheck -d example.com -a 30

# JSON output for pipes and monitoring
sslcheck -f domains.txt --json | jq '.[] | select(.days_remaining < 30)'

# cron-friendly with log file
sslcheck -f /etc/domains.txt --log-file /var/log/sslcheck.log

# internal PKI: trust your own CA so validation really passes
sslcheck -f internal.txt --ca-file /etc/pki/internal-ca.pem

# appliances you can't re-issue: report expiry, warn instead of failing
sslcheck -f appliances.txt --allow-untrusted
```

Create a sample file to get started:

```bash
sslcheck --create-sample
```

## Flags

| Flag | Description |
|------|-------------|
| `-d, --domains` | Domains to check (space-separated) |
| `-f, --file` | File with one domain per line |
| `-c, --config` | Path to config file |
| `-t, --threshold`, `-a, --alert` | Days before expiry to warn (default `15`) |
| `-p, --port` | TLS port (default `443`) |
| `-w, --workers` | Concurrent workers (default `10`) |
| `--json` | Emit JSON instead of human-readable output |
| `--ca-file` | Extra CA bundle (PEM) to trust, on top of the system store |
| `--ca-path` | Directory of extra trusted CAs (OpenSSL hashed dir) |
| `--allow-untrusted` | Report validation failures as `valid` + warning instead of `untrusted` |
| `--no-color` | Disable colors |
| `--log-file` | Append results to a log file |
| `--create-sample` | Write `domains.txt` with example domains |

## Config file

`sslcheck` looks for `sslcheck.conf` in `./` then `~/` — the local file wins. Passing `-c <path>` replaces that search entirely: the named file is the only one read, and a missing path is an error rather than a silent fallback.

```ini
[DEFAULT]
domains = example.com, google.com, github.com
alert_days = 30
```

Priority: CLI flags → file (`-f`) → config.

## Output modes

**Interactive TTY** — live per-domain spinner with elapsed time, updating in place.

**Piped / redirected** — animation auto-disables, one line per completed domain, then the summary. Safe for `tee`, log files, and cron.

**`--json`** — array of `{domain, port, status, expiry_date, days_remaining, verified, validation_error, error}`. Nothing else on stdout. `verified` is `false` whenever the chain failed validation, regardless of `status` or exit code, so a monitoring system can pick its own severity.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All certificates valid (including "expiring soon", and "unverified" under `--allow-untrusted`) |
| `1`  | At least one expired, untrusted, or unreachable cert, or invalid invocation |

## Cron

```cron
0 2 * * * /usr/local/bin/sslcheck -f /etc/domains.txt -a 30 --log-file /var/log/sslcheck.log
```

When stdout isn't a TTY, colors and animation are off automatically — no ANSI codes end up in your log.

## Trust and validation

A certificate that fails chain validation is still parsed for its real expiry date — you see `2028-09-07`, not a generic error. But it is never reported as `valid`: it gets its own `untrusted` status and exits `1`.

| Status | Meaning |
|--------|---------|
| `valid` | Chain verified, expiry beyond the threshold |
| `expiring` | Chain verified, expires within the threshold |
| `untrusted` | Certificate read, but chain validation failed (self-signed, untrusted CA, hostname mismatch) |
| `expired` | Past `notAfter` |
| `error` | No certificate could be read (DNS, timeout, connection refused, protocol failure) |

Two escape hatches, for the two things `untrusted` usually means:

**Internal PKI** — the chain is fine, your CA just isn't in the system trust store. `--ca-file` / `--ca-path` add trust anchors *on top of* the system store, so a mixed inventory of public and internal hosts validates correctly in a single run. This is the preferred fix: validation genuinely passes, and `untrusted` keeps meaning something.

```bash
sslcheck -f all-hosts.txt --ca-file /etc/pki/internal-ca.pem
```

**Certificates you can't fix** — appliances, iDRAC/BMC, gear with a baked-in self-signed cert. `--allow-untrusted` downgrades `untrusted` to `valid` with a visible `⚠` on the row and an `unverified` line in the summary, and exits `0`. Use it so a nightly cron doesn't cry wolf every night; `verified: false` is still in the JSON either way.

```bash
sslcheck -f appliances.txt --allow-untrusted
```

`--allow-untrusted` never masks an expired certificate — `expired` is checked first.

## Behavior notes

- 10-second socket timeout per domain.
- SNI is sent (`server_hostname`).
- A cert that fails validation costs two connections: one verifying, one to read the raw DER.
- Expiry is compared by date, not timestamp.

## License

GPL-3.0 — © 2025 Juan Vassallo
