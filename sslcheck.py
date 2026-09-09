#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSL Certificate Checker
Copyright (C) 2025 Juan Vassallo

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from datetime import datetime
import ssl
import socket
import argparse
import sys
import os
import time
import json
from threading import Thread, Lock
import concurrent.futures
import configparser
import logging


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GRAY = '\033[90m'
    END = '\033[0m'

    @staticmethod
    def disable():
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.GRAY = ''
        Colors.END = ''


DAYS_THRESHOLD = 15
DEFAULT_PORT = 443
CONNECT_TIMEOUT = 10

SPINNER_CHARS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

DOT = '●'
INDENT = '  '

STATUS_STYLE = {
    'valid':     (lambda: Colors.GREEN,   'valid'),
    'expiring':  (lambda: Colors.YELLOW,  'expiring'),
    'untrusted': (lambda: Colors.MAGENTA, 'untrusted'),
    'expired':   (lambda: Colors.RED,     'expired'),
    'error':     (lambda: Colors.RED,     'error'),
}


def load_config(config_file=None):
    """Load configuration.

    An explicit --config replaces the default search path entirely, so the
    file the user named is the file that is used. Otherwise ./sslcheck.conf
    wins over ~/sslcheck.conf.
    """
    config = configparser.ConfigParser()
    if config_file:
        config_files = [config_file]
    else:
        config_files = [
            path for path in (os.path.expanduser('~/sslcheck.conf'), 'sslcheck.conf')
            if os.path.exists(path)
        ]
    if config_files:
        config.read(config_files)
        return config
    return None


def parse_domains_from_config(config):
    domains = []
    if config and config.has_option('DEFAULT', 'domains'):
        domains_str = config.get('DEFAULT', 'domains')
        domains = [d.strip() for d in domains_str.split(',') if d.strip()]
    return domains


def get_alert_days_from_config(config):
    if config and config.has_option('DEFAULT', 'alert_days'):
        try:
            return int(config.get('DEFAULT', 'alert_days'))
        except ValueError:
            pass
    return DAYS_THRESHOLD


def setup_logging(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(log_file)],
    )


def _asn1_len(data, i):
    """Parse an ASN.1 DER length starting at offset i. Returns (length, next_offset)."""
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    length = 0
    for _ in range(n):
        length = (length << 8) | data[i]
        i += 1
    return length, i


def _asn1_skip(data, i):
    """Skip one ASN.1 TLV element. Returns offset past the element."""
    i += 1
    length, i = _asn1_len(data, i)
    return i + length


def _extract_not_after(der):
    """Extract notAfter date from an X.509 DER-encoded certificate."""
    i = 0
    if der[i] != 0x30:
        raise ValueError("expected outer SEQUENCE")
    _, i = _asn1_len(der, i + 1)
    if der[i] != 0x30:
        raise ValueError("expected tbsCertificate SEQUENCE")
    _, i = _asn1_len(der, i + 1)
    if der[i] == 0xA0:  # [0] EXPLICIT version, optional
        i = _asn1_skip(der, i)
    i = _asn1_skip(der, i)  # serialNumber
    i = _asn1_skip(der, i)  # signature AlgorithmIdentifier
    i = _asn1_skip(der, i)  # issuer
    if der[i] != 0x30:
        raise ValueError("expected validity SEQUENCE")
    _, i = _asn1_len(der, i + 1)
    i = _asn1_skip(der, i)  # notBefore
    tag = der[i]
    i += 1
    length, i = _asn1_len(der, i)
    time_str = der[i:i + length].decode('ascii')
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSSZ
        return datetime.strptime(time_str, '%y%m%d%H%M%SZ').date()
    if tag == 0x18:  # GeneralizedTime: YYYYMMDDHHMMSSZ
        return datetime.strptime(time_str, '%Y%m%d%H%M%SZ').date()
    raise ValueError(f"unexpected time tag 0x{tag:02x}")


def build_context(ca_file=None, ca_path=None):
    """Verifying context trusting the system store plus any extra anchors.

    load_verify_locations() adds to the default store rather than replacing it,
    so a mixed inventory of public and internal-PKI hosts validates in one run.
    """
    context = ssl.create_default_context()
    if ca_file or ca_path:
        context.load_verify_locations(cafile=ca_file, capath=ca_path)
    return context


def get_certificate_expiry(domain, port=DEFAULT_PORT, ca_file=None, ca_path=None):
    """Return (expiry_date, error, validation_error).

    error            — no certificate could be read at all (network/protocol).
    validation_error — a certificate was read but failed chain validation
                       (self-signed, untrusted CA, hostname mismatch, expired).
    """
    try:
        context = build_context(ca_file, ca_path)
        with socket.create_connection((domain, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').date(), None, None
    except ssl.SSLCertVerificationError as e:
        # Fall through — retry unverified so we can still read notAfter, but
        # keep why validation failed: an unverifiable cert is never "valid".
        validation_error = getattr(e, 'verify_message', None) or str(e)
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError, ValueError, KeyError) as e:
        return None, str(e), None

    # Fetch the raw DER without validation and parse notAfter so we can report
    # EXPIRED/UNTRUSTED with a real date instead of a generic error.
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return None, "server presented no certificate", None
        return _extract_not_after(der), None, validation_error
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError, ValueError, KeyError, IndexError) as e:
        return None, str(e), validation_error


def create_sample_domains_file(filename):
    sample_domains = ["google.com", "github.com", "stackoverflow.com", "cloudflare.com", "mozilla.org"]
    with open(filename, "w") as file:
        for domain in sample_domains:
            file.write(f"{domain}\n")
    print(f"{INDENT}{Colors.GREEN}✓{Colors.END} wrote {Colors.BOLD}{filename}{Colors.END} {Colors.GRAY}({len(sample_domains)} domains){Colors.END}")


def classify(days_remaining, error, validation_error, threshold, allow_untrusted=False):
    if error:
        return 'error'
    if days_remaining <= 0:
        return 'expired'
    if validation_error and not allow_untrusted:
        return 'untrusted'
    if days_remaining <= threshold:
        return 'expiring'
    return 'valid'


def main():
    parser = argparse.ArgumentParser(
        description="SSL Certificate Checker — monitor SSL certificate expiration across multiple domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sslcheck -f domains.txt
  sslcheck -d example.com google.com
  sslcheck -d example.com -a 30
  sslcheck -c /path/to/custom.conf
  sslcheck -f sites.txt -t 30 -p 443
  sslcheck -d example.com --json | jq '.[] | select(.days_remaining < 30)'
  sslcheck --create-sample
  sslcheck -f domains.txt --log-file /var/log/sslcheck.log
  sslcheck -f internal.txt --ca-file /etc/pki/internal-ca.pem
  sslcheck -f appliances.txt --allow-untrusted
        """
    )
    parser.add_argument("-f", "--file", help="File containing list of domains (one per line)")
    parser.add_argument("-d", "--domains", nargs='+', help="List of domains to check (space-separated)")
    parser.add_argument("-c", "--config", help="Custom configuration file path")
    parser.add_argument("-t", "--threshold", type=int, help=f"Days threshold to consider as expiring soon (default: {DAYS_THRESHOLD})")
    parser.add_argument("-a", "--alert", type=int, help="Alias for --threshold")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help=f"SSL port to check (default: {DEFAULT_PORT})")
    parser.add_argument("--create-sample", action="store_true", help="Create sample 'domains.txt' file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of concurrent workers (default: 10)")
    parser.add_argument("--log-file", help="Log file path for cron job integration")
    parser.add_argument("--json", action="store_true", help="Emit results as JSON (disables all decorative output)")
    parser.add_argument("--ca-file", help="Extra CA bundle (PEM) to trust, in addition to the system store")
    parser.add_argument("--ca-path", help="Directory of extra trusted CA certificates (OpenSSL hashed dir)")
    parser.add_argument("--allow-untrusted", action="store_true",
                        help="Treat certificates that fail chain validation as VALID with a warning "
                             "instead of UNTRUSTED (keeps exit 0; for internal PKI and appliances)")

    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    for name, value in (("--threshold", args.threshold), ("--alert", args.alert)):
        if value is not None and value < 0:
            parser.error(f"{name} must not be negative")
    if args.config and not os.path.exists(args.config):
        parser.error(f"config file '{args.config}' not found")
    if args.ca_file and not os.path.isfile(args.ca_file):
        parser.error(f"CA file '{args.ca_file}' not found")
    if args.ca_path and not os.path.isdir(args.ca_path):
        parser.error(f"CA directory '{args.ca_path}' not found")
    if args.ca_file or args.ca_path:
        # Fail fast on an unreadable/malformed bundle rather than once per worker.
        try:
            build_context(args.ca_file, args.ca_path)
        except (ssl.SSLError, OSError) as e:
            parser.error(f"could not load CA certificates: {e}")

    is_tty = sys.stdout.isatty()
    json_mode = args.json
    if args.no_color or not is_tty or json_mode:
        Colors.disable()
    animate = is_tty and not json_mode

    if args.log_file:
        setup_logging(args.log_file)

    if args.create_sample:
        create_sample_domains_file("domains.txt")
        return

    config = load_config(args.config)

    threshold = args.threshold if args.threshold is not None else args.alert
    if threshold is None:
        threshold = get_alert_days_from_config(config)

    domains = []
    if args.domains:
        domains = args.domains
    elif args.file:
        if not os.path.exists(args.file):
            print(f"{INDENT}{Colors.RED}Error:{Colors.END} file '{args.file}' not found", file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.file, "r") as file:
                domains = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"{INDENT}{Colors.RED}Error:{Colors.END} could not read '{args.file}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        domains = parse_domains_from_config(config)

    if not domains:
        print(f"{INDENT}{Colors.RED}Error:{Colors.END} no domains specified", file=sys.stderr)
        print(f"{INDENT}{Colors.GRAY}Pass -d <domain>, -f <file>, or set domains in sslcheck.conf.{Colors.END}", file=sys.stderr)
        print(f"{INDENT}{Colors.GRAY}Run --create-sample to write an example file.{Colors.END}", file=sys.stderr)
        sys.exit(1)

    if args.log_file:
        logging.info(f"SSL Certificate check started for {len(domains)} domains")
        logging.info(f"Domains: {', '.join(domains)}")
        logging.info(f"Port: {args.port}, Threshold: {threshold} days")

    current_date = datetime.now().date()

    started = time.monotonic()
    name_width = min(max(len(d) for d in domains), 44)

    if not json_mode:
        meta = f"{len(domains)} domain{'s' if len(domains) != 1 else ''} · port {args.port} · threshold {threshold}d"
        print(f"{INDENT}{Colors.BOLD}sslcheck{Colors.END} {Colors.GRAY}{meta}{Colors.END}")
        print()

    state = {d: {'status': 'pending', 'start': time.monotonic(), 'elapsed': None} for d in domains}
    state_lock = Lock()
    spinner_pos = [0]
    lines_rendered = [0]
    stop_spinner = [False]

    def render_live():
        """Render status block in-place; called under state_lock."""
        out = sys.stdout
        if lines_rendered[0]:
            out.write(f'\033[{lines_rendered[0]}A')
        spin = SPINNER_CHARS[spinner_pos[0] % len(SPINNER_CHARS)]
        count = 0
        for d in domains:
            st = state[d]
            if st['status'] == 'pending':
                elapsed = time.monotonic() - st['start']
                glyph, label = f"{Colors.GRAY}{spin}", 'checking'
            elif st['status'] == 'completed':
                elapsed, glyph, label = st['elapsed'], f"{Colors.GREEN}{DOT}", 'done'
            else:
                elapsed, glyph, label = st['elapsed'], f"{Colors.RED}{DOT}", 'failed'
            line = (f"{INDENT}{glyph}{Colors.END} {d:<{name_width}}  "
                    f"{Colors.GRAY}{label:<9}{elapsed:>4.1f}s{Colors.END}")
            out.write(f'\r\033[K{line}\n')
            count += 1
        done = sum(1 for d in domains if state[d]['status'] != 'pending')
        out.write(f'\r\033[K{INDENT}{Colors.GRAY}{done} of {len(domains)} checked{Colors.END}\n')
        count += 1
        lines_rendered[0] = count
        out.flush()

    def mark_done(domain, status):
        with state_lock:
            st = state[domain]
            st['status'] = status
            st['elapsed'] = time.monotonic() - st['start']
            if animate:
                render_live()
            elif not json_mode:
                color = Colors.GREEN if status == 'completed' else Colors.RED
                print(f"{INDENT}{color}{DOT}{Colors.END} {domain:<{name_width}}  "
                      f"{Colors.GRAY}{st['elapsed']:.1f}s{Colors.END}")

    def check_domain(domain):
        expiry_date, error, validation_error = get_certificate_expiry(
            domain, args.port, args.ca_file, args.ca_path)
        if expiry_date:
            days_remaining = (expiry_date - current_date).days
            mark_done(domain, 'completed' if not validation_error or args.allow_untrusted else 'error')
            return {'domain': domain, 'port': args.port, 'expiry_date': expiry_date,
                    'days_remaining': days_remaining, 'error': None,
                    'validation_error': validation_error}
        mark_done(domain, 'error')
        return {'domain': domain, 'port': args.port, 'expiry_date': None,
                'days_remaining': None, 'error': error,
                'validation_error': validation_error}

    def spinner_ticker():
        while not stop_spinner[0]:
            with state_lock:
                if not any(state[d]['status'] == 'pending' for d in domains):
                    break
                spinner_pos[0] += 1
                render_live()
            time.sleep(0.1)

    results = []
    try:
        if animate:
            sys.stdout.write('\033[?25l')
            sys.stdout.flush()
            with state_lock:
                render_live()
            Thread(target=spinner_ticker, daemon=True).start()

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(check_domain, d) for d in domains]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        if animate:
            stop_spinner[0] = True
            with state_lock:
                if lines_rendered[0]:
                    sys.stdout.write(f'\033[{lines_rendered[0]}A')
                    for _ in range(lines_rendered[0]):
                        sys.stdout.write('\033[K\n')
                    sys.stdout.write(f'\033[{lines_rendered[0]}A')
                    sys.stdout.flush()
        elif not json_mode:
            print()
    finally:
        if animate:
            sys.stdout.write('\033[?25h')
            sys.stdout.flush()

    results.sort(key=lambda x: (x['error'] is not None, x['days_remaining'] if x['days_remaining'] is not None else -999))

    valid_count = warning_count = untrusted_count = expired_count = error_count = 0
    for r in results:
        r['status'] = classify(r['days_remaining'], r['error'], r['validation_error'],
                               threshold, args.allow_untrusted)
        if r['status'] == 'valid':
            valid_count += 1
        elif r['status'] == 'expiring':
            warning_count += 1
        elif r['status'] == 'untrusted':
            untrusted_count += 1
        elif r['status'] == 'expired':
            expired_count += 1
        else:
            error_count += 1
    unverified_count = sum(
        1 for r in results if r['validation_error'] and r['status'] not in ('untrusted', 'expired')
    )

    if json_mode:
        payload = [{
            'domain': r['domain'],
            'port': r['port'],
            'status': r['status'],
            'expiry_date': r['expiry_date'].isoformat() if r['expiry_date'] else None,
            'days_remaining': r['days_remaining'],
            'verified': r['error'] is None and r['validation_error'] is None,
            'validation_error': r['validation_error'],
            'error': r['error'],
        } for r in results]
        print(json.dumps(payload, indent=2))
    else:
        for r in results:
            color_fn, label = STATUS_STYLE[r['status']]
            color = color_fn()
            row = f"{INDENT}{color}{DOT}{Colors.END} {r['domain']:<{name_width}}  {color}{label:<10}{Colors.END}"
            if r['error']:
                print(f"{row} {Colors.GRAY}{'':<24}{r['error'][:56]}{Colors.END}")
                continue
            days = r['days_remaining']
            when = f"{days}d left" if days > 0 else f"{-days}d ago"
            note = ''
            if r['validation_error'] and r['status'] != 'expired':
                mark = '' if r['status'] == 'untrusted' else '⚠ '
                note = f"{mark}{r['validation_error'][:44]}"
            detail = f"{str(r['expiry_date']):<12}{when:<11}{note}".rstrip()
            print(f"{row} {Colors.GRAY}{detail}{Colors.END}")

        print()
        tally = [
            (valid_count, 'valid', Colors.GREEN),
            (warning_count, 'expiring', Colors.YELLOW),
            (untrusted_count, 'untrusted', Colors.MAGENTA),
            (expired_count, 'expired', Colors.RED),
            (error_count, 'error' if error_count == 1 else 'errors', Colors.RED),
        ]
        parts = [f"{color}{count} {label}{Colors.END}" for count, label, color in tally if count]
        print(f"{INDENT}{f'{Colors.GRAY} · {Colors.END}'.join(parts)}")
        if unverified_count:
            print(f"{INDENT}{Colors.YELLOW}{unverified_count} unverified{Colors.END} "
                  f"{Colors.GRAY}· reported valid via --allow-untrusted{Colors.END}")

        needs_attention = expired_count + untrusted_count + error_count
        if needs_attention:
            noun, verb = ('domain', 'needs') if needs_attention == 1 else ('domains', 'need')
            print(f"{INDENT}{Colors.RED}✗{Colors.END} {needs_attention} {noun} {verb} attention")
        elif warning_count or unverified_count:
            print(f"{INDENT}{Colors.YELLOW}!{Colors.END} monitoring needed")
        else:
            print(f"{INDENT}{Colors.GREEN}✓{Colors.END} all certificates valid")
        print(f"{INDENT}{Colors.GRAY}Done in {time.monotonic() - started:.1f}s{Colors.END}")

    if args.log_file:
        logging.info("SSL Certificate check completed")
        logging.info(f"Results: {valid_count} valid, {warning_count} expiring soon, {untrusted_count} untrusted, {expired_count} expired, {error_count} errors, {unverified_count} unverified")
        for r in results:
            if r['error']:
                logging.error(f"{r['domain']}: {r['error']}")
            elif r['days_remaining'] is not None:
                if r['status'] == 'expired':
                    logging.critical(f"{r['domain']}: Certificate EXPIRED on {r['expiry_date']}")
                elif r['status'] == 'untrusted':
                    logging.critical(f"{r['domain']}: Certificate FAILED validation ({r['validation_error']}), expires {r['expiry_date']}")
                elif r['validation_error']:
                    logging.warning(f"{r['domain']}: Certificate unverified ({r['validation_error']}), expires {r['expiry_date']} in {r['days_remaining']} days")
                elif r['days_remaining'] <= threshold:
                    logging.warning(f"{r['domain']}: Certificate expires in {r['days_remaining']} days on {r['expiry_date']}")
                else:
                    logging.info(f"{r['domain']}: Certificate valid for {r['days_remaining']} days (expires {r['expiry_date']})")

    sys.exit(1 if expired_count or error_count or untrusted_count else 0)


if __name__ == "__main__":
    main()
