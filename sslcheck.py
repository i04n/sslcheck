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


def load_config(config_file=None):
    """Load configuration from file"""
    config = configparser.ConfigParser()
    config_files = []
    if config_file:
        config_files.append(config_file)
    home_config = os.path.expanduser('~/sslcheck.conf')
    if os.path.exists(home_config):
        config_files.append(home_config)
    local_config = 'sslcheck.conf'
    if os.path.exists(local_config):
        config_files.append(local_config)
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


def get_certificate_expiry(domain, port=DEFAULT_PORT):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').date(), None
    except ssl.SSLCertVerificationError:
        pass  # fall through — retry unverified so we can still read notAfter
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError, ValueError, KeyError) as e:
        return None, str(e)

    # Verification failed (expired / self-signed / hostname mismatch / untrusted CA).
    # Fetch the raw DER without validation and parse notAfter so we can report
    # EXPIRED/EXPIRING instead of a generic error.
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return None, "server presented no certificate"
        return _extract_not_after(der), None
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError, ValueError, KeyError, IndexError) as e:
        return None, str(e)


def create_sample_domains_file(filename):
    sample_domains = ["google.com", "github.com", "stackoverflow.com", "cloudflare.com", "mozilla.org"]
    with open(filename, "w") as file:
        for domain in sample_domains:
            file.write(f"{domain}\n")
    print(f"{Colors.GREEN}✓{Colors.END} Sample domains file created: {Colors.CYAN}{filename}{Colors.END}")


def classify(days_remaining, error, threshold):
    if error:
        return 'error'
    if days_remaining <= 0:
        return 'expired'
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

    args = parser.parse_args()

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
            print(f"{Colors.RED}Error:{Colors.END} File '{args.file}' not found", file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.file, "r") as file:
                domains = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"{Colors.RED}Error reading file:{Colors.END} {e}", file=sys.stderr)
            sys.exit(1)
    else:
        domains = parse_domains_from_config(config)

    if not domains:
        print(f"{Colors.RED}Error:{Colors.END} No domains specified", file=sys.stderr)
        print(f"{Colors.YELLOW}Tip:{Colors.END} Use -d, -f, or configure domains in sslcheck.conf", file=sys.stderr)
        print(f"{Colors.YELLOW}Tip:{Colors.END} Use --create-sample to create an example file", file=sys.stderr)
        sys.exit(1)

    if args.log_file:
        logging.info(f"SSL Certificate check started for {len(domains)} domains")
        logging.info(f"Domains: {', '.join(domains)}")
        logging.info(f"Port: {args.port}, Threshold: {threshold} days")

    current_date = datetime.now().date()

    if not json_mode:
        print(f"{Colors.BOLD}SSL Certificate Checker{Colors.END}")
        print(f"{Colors.GRAY}{len(domains)} domain(s) · port {args.port} · threshold {threshold}d · {args.workers} workers{Colors.END}")
        print(f"{Colors.GRAY}{'─' * 72}{Colors.END}")

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
                line = f"{Colors.YELLOW}{spin}{Colors.END} {d:<45} {Colors.GRAY}checking… {elapsed:>4.1f}s{Colors.END}"
            elif st['status'] == 'completed':
                line = f"{Colors.GREEN}✓{Colors.END} {d:<45} {Colors.GRAY}done      {st['elapsed']:>4.1f}s{Colors.END}"
            else:
                line = f"{Colors.RED}✗{Colors.END} {d:<45} {Colors.GRAY}error     {st['elapsed']:>4.1f}s{Colors.END}"
            out.write(f'\r\033[K{line}\n')
            count += 1
        done = sum(1 for d in domains if state[d]['status'] != 'pending')
        out.write(f'\r\033[K{Colors.CYAN}{done}/{len(domains)} complete{Colors.END}\n')
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
                icon = f"{Colors.GREEN}✓{Colors.END}" if status == 'completed' else f"{Colors.RED}✗{Colors.END}"
                print(f"{icon} {domain} ({st['elapsed']:.1f}s)")

    def check_domain(domain):
        expiry_date, error = get_certificate_expiry(domain, args.port)
        if expiry_date:
            days_remaining = (expiry_date - current_date).days
            mark_done(domain, 'completed')
            return {'domain': domain, 'port': args.port, 'expiry_date': expiry_date,
                    'days_remaining': days_remaining, 'error': None}
        mark_done(domain, 'error')
        return {'domain': domain, 'port': args.port, 'expiry_date': None,
                'days_remaining': None, 'error': error}

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
    finally:
        if animate:
            sys.stdout.write('\033[?25h')
            sys.stdout.flush()

    results.sort(key=lambda x: (x['error'] is not None, x['days_remaining'] if x['days_remaining'] is not None else -999))

    valid_count = warning_count = expired_count = error_count = 0
    for r in results:
        c = classify(r['days_remaining'], r['error'], threshold)
        if c == 'valid':
            valid_count += 1
        elif c == 'expiring':
            warning_count += 1
        elif c == 'expired':
            expired_count += 1
        else:
            error_count += 1

    if json_mode:
        payload = [{
            'domain': r['domain'],
            'port': r['port'],
            'status': classify(r['days_remaining'], r['error'], threshold),
            'expiry_date': r['expiry_date'].isoformat() if r['expiry_date'] else None,
            'days_remaining': r['days_remaining'],
            'error': r['error'],
        } for r in results]
        print(json.dumps(payload, indent=2))
    else:
        print(f"{Colors.GRAY}{'─' * 72}{Colors.END}")
        print(f"{Colors.BOLD}Results{Colors.END}")
        print(f"{Colors.GRAY}{'─' * 72}{Colors.END}")
        for r in results:
            domain = r['domain']
            if r['error']:
                print(f"{Colors.RED}✗{Colors.END} {domain:<35} {Colors.RED}{'ERROR':<10}{Colors.END} {Colors.GRAY}{r['error'][:50]}{Colors.END}")
            else:
                days = r['days_remaining']
                if days <= 0:
                    color, icon, text = Colors.RED, '🔴', 'EXPIRED'
                elif days <= threshold:
                    color, icon, text = Colors.YELLOW, '🟡', 'EXPIRING'
                else:
                    color, icon, text = Colors.GREEN, '🟢', 'VALID'
                print(f"{icon} {domain:<35} {color}{text:<10}{Colors.END} {Colors.GRAY}expires {r['expiry_date']} ({days}d){Colors.END}")
        print(f"{Colors.GRAY}{'─' * 72}{Colors.END}")

        total = len(domains)
        bar_width = 30

        def bar(count, color):
            filled = int(bar_width * count / total) if total else 0
            return f"{color}{'█' * filled}{Colors.GRAY}{'░' * (bar_width - filled)}{Colors.END}"

        print(f"{Colors.BOLD}Summary{Colors.END}")
        if valid_count:
            print(f"  {Colors.GREEN}valid    {Colors.END} {bar(valid_count, Colors.GREEN)}  {valid_count}/{total}")
        if warning_count:
            print(f"  {Colors.YELLOW}expiring {Colors.END} {bar(warning_count, Colors.YELLOW)}  {warning_count}/{total}")
        if expired_count:
            print(f"  {Colors.RED}expired  {Colors.END} {bar(expired_count, Colors.RED)}  {expired_count}/{total}")
        if error_count:
            print(f"  {Colors.RED}errors   {Colors.END} {bar(error_count, Colors.RED)}  {error_count}/{total}")
        print(f"{Colors.GRAY}{'─' * 72}{Colors.END}")

        if expired_count or error_count:
            print(f"{Colors.RED}✗ attention required{Colors.END}")
        elif warning_count:
            print(f"{Colors.YELLOW}! monitoring needed{Colors.END}")
        else:
            print(f"{Colors.GREEN}✓ all certificates healthy{Colors.END}")

    if args.log_file:
        logging.info("SSL Certificate check completed")
        logging.info(f"Results: {valid_count} valid, {warning_count} expiring soon, {expired_count} expired, {error_count} errors")
        for r in results:
            if r['error']:
                logging.error(f"{r['domain']}: {r['error']}")
            elif r['days_remaining'] is not None:
                if r['days_remaining'] <= 0:
                    logging.critical(f"{r['domain']}: Certificate EXPIRED on {r['expiry_date']}")
                elif r['days_remaining'] <= threshold:
                    logging.warning(f"{r['domain']}: Certificate expires in {r['days_remaining']} days on {r['expiry_date']}")
                else:
                    logging.info(f"{r['domain']}: Certificate valid for {r['days_remaining']} days (expires {r['expiry_date']})")

    sys.exit(1 if expired_count or error_count else 0)


if __name__ == "__main__":
    main()
