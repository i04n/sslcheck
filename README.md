# sslcheck

Single-file, zero-dependency SSL/TLS certificate expiry monitor.

```bash
sslcheck -d example.com
```

```
SSL Certificate Checker
1 domain(s) · port 443 · threshold 15d · 10 workers
────────────────────────────────────────────────────────────────────────
Results
────────────────────────────────────────────────────────────────────────
🟢 example.com                         VALID      expires 2026-08-14 (112d)
────────────────────────────────────────────────────────────────────────
Summary
  valid      ██████████████████████████████  1/1
────────────────────────────────────────────────────────────────────────
✓ all certificates healthy
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
| `--no-color` | Disable colors |
| `--log-file` | Append results to a log file |
| `--create-sample` | Write `domains.txt` with example domains |

## Config file

`sslcheck` looks for `sslcheck.conf` in `./` and `~/`, or use `-c <path>`.

```ini
[DEFAULT]
domains = example.com, google.com, github.com
alert_days = 30
```

Priority: CLI flags → file (`-f`) → config.

## Output modes

**Interactive TTY** — live per-domain spinner with elapsed time, updating in place.

**Piped / redirected** — animation auto-disables, one line per completed domain, then the summary. Safe for `tee`, log files, and cron.

**`--json`** — array of `{domain, port, status, expiry_date, days_remaining, error}`. Nothing else on stdout.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All certificates valid (including "expiring soon") |
| `1`  | At least one expired cert, connection error, or invalid invocation |

## Cron

```cron
0 2 * * * /usr/local/bin/sslcheck -f /etc/domains.txt -a 30 --log-file /var/log/sslcheck.log
```

When stdout isn't a TTY, colors and animation are off automatically — no ANSI codes end up in your log.

## Behavior notes

- Certificates that fail chain validation (expired, self-signed, untrusted CA, hostname mismatch) are still parsed so you can see the real expiry. Only network or protocol failures become `ERROR`.
- 10-second socket timeout per domain.
- SNI is sent (`server_hostname`).

## License

GPL-3.0 — © 2025 Juan Vassallo
