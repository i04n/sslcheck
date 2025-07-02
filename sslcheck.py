from datetime import datetime
import OpenSSL
import ssl
import argparse
import sys
import os
import time
from threading import Thread, Lock
from queue import Queue
import concurrent.futures
import itertools

# Color codes for terminal output
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
        Colors.END = ''

DAYS_THRESHOLD = 15  # Days threshold to consider as "expiring soon"
DEFAULT_PORT = 443

# Spinner characters for loading animation
SPINNER_CHARS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

def get_certificate_expiry(domain, port=DEFAULT_PORT):
    try:
        cert = ssl.get_server_certificate((domain, port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        bytes_expiry = x509.get_notAfter()
        timestamp = bytes_expiry.decode('utf-8')
        expiry_date = datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date()
        return expiry_date, None
    except (ssl.SSLError, OpenSSL.crypto.Error, ValueError, ConnectionError, OSError) as e:
        return None, str(e)

def create_sample_domains_file(filename):
    sample_domains = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "cloudflare.com",
        "mozilla.org"
    ]
    with open(filename, "w") as file:
        for domain in sample_domains:
            file.write(f"{domain}\n")
    print(f"{Colors.GREEN}✓{Colors.END} Sample domains file created: {Colors.CYAN}{filename}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description="🔒 SSL Certificate Checker - Monitor SSL certificate expiration for multiple domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
📋 Usage Examples:
  %(prog)s -f domains.txt
  %(prog)s -f sites.txt -t 30 -p 443
  %(prog)s --create-sample
  %(prog)s -f domains.txt --no-color
        """
    )
    
    parser.add_argument("-f", "--file", 
                       help="File containing list of domains (one per line)")
    parser.add_argument("-t", "--threshold", type=int, default=DAYS_THRESHOLD,
                       help=f"Days threshold to consider as expiring soon (default: {DAYS_THRESHOLD})")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                       help=f"SSL port to check (default: {DEFAULT_PORT})")
    parser.add_argument("--create-sample", action="store_true",
                       help="Create sample 'domains.txt' file")
    parser.add_argument("--no-color", action="store_true",
                       help="Disable colored output")
    parser.add_argument("-w", "--workers", type=int, default=10,
                       help="Number of concurrent workers (default: 10)")
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    if args.create_sample:
        create_sample_domains_file("domains.txt")
        return
    
    if not args.file:
        print(f"{Colors.RED}❌ Error:{Colors.END} You must specify a domains file using -f/--file")
        print(f"{Colors.YELLOW}💡 Tip:{Colors.END} Use --help to see available options")
        print(f"{Colors.YELLOW}💡 Tip:{Colors.END} Use --create-sample to create an example file")
        sys.exit(1)
    
    if not os.path.exists(args.file):
        print(f"{Colors.RED}❌ Error:{Colors.END} File '{Colors.CYAN}{args.file}{Colors.END}' not found")
        sys.exit(1)
    
    try:
        with open(args.file, "r") as file:
            domains = [line.strip() for line in file.readlines() if line.strip()]
    except Exception as e:
        print(f"{Colors.RED}❌ Error reading file:{Colors.END} {e}")
        sys.exit(1)
    
    if not domains:
        print(f"{Colors.RED}❌ Error:{Colors.END} File '{Colors.CYAN}{args.file}{Colors.END}' is empty or contains no valid domains")
        sys.exit(1)
    
    print(f"{Colors.BOLD}{Colors.BLUE}🔒 SSL Certificate Checker{Colors.END}")
    print(f"{Colors.CYAN}📋 Checking {len(domains)} domain(s) on port {args.port}{Colors.END}")
    print(f"{Colors.YELLOW}⚠️  Warning threshold: {args.threshold} days{Colors.END}")
    print(f"{Colors.MAGENTA}👥 Using {args.workers} concurrent workers{Colors.END}")
    print("═" * 80)
    
    current_date = datetime.now().date()
    results = []
    display_lock = Lock()
    domain_status = {domain: {'status': 'pending', 'spinner_pos': 0} for domain in domains}
    
    def update_display():
        """Update the display with current status of all domains"""
        with display_lock:
            # Calculate current progress
            remaining = len([d for d in domains if domain_status[d]['status'] == 'pending'])
            completed = len([d for d in domains if domain_status[d]['status'] in ['completed', 'error']])
            
            # Move cursor up to overwrite previous content
            if hasattr(update_display, 'lines_printed'):
                # Move cursor up by the number of lines we printed last time
                print(f"\033[{update_display.lines_printed}A", end="")
            
            lines_printed = 0
            
            # Show status for all domains
            for i, domain in enumerate(domains):
                status_info = domain_status[domain]
                if status_info['status'] == 'pending':
                    spinner = SPINNER_CHARS[status_info['spinner_pos'] % len(SPINNER_CHARS)]
                    print(f"\r{Colors.YELLOW}{spinner}{Colors.END} {domain[:20]:20} checking...{' ' * 20}", end="  ")
                elif status_info['status'] == 'completed':
                    print(f"\r{Colors.GREEN}✓{Colors.END} {domain[:20]:20} done{' ' * 23}", end="  ")
                elif status_info['status'] == 'error':
                    print(f"\r{Colors.RED}✗{Colors.END} {domain[:20]:20} error{' ' * 22}", end="  ")
                
                # New line every 3 domains
                if (i + 1) % 3 == 0 or i == len(domains) - 1:
                    print(f"{' ' * 50}")  # Clear rest of line and go to next
                    lines_printed += 1
            
            # Progress summary line
            progress_text = f"{Colors.CYAN}Progress: {completed}/{len(domains)} domains completed"
            if remaining > 0:
                progress_text += f", {remaining} checking..."
            else:
                progress_text += f" - All done!"
            progress_text += f"{Colors.END}"
            
            print(f"\r{progress_text}{' ' * 50}")
            lines_printed += 1
            
            # Store the number of lines we printed for next update
            update_display.lines_printed = lines_printed
            
            sys.stdout.flush()
    
    def check_domain(domain):
        result = get_certificate_expiry(domain, args.port)
        if len(result) == 2:
            expiry_date, error = result
            if expiry_date:
                days_remaining = (expiry_date - current_date).days
                domain_status[domain]['status'] = 'completed'
                update_display()
                return {
                    'domain': domain,
                    'expiry_date': expiry_date,
                    'days_remaining': days_remaining,
                    'error': None
                }
            else:
                domain_status[domain]['status'] = 'error'
                update_display()
                return {
                    'domain': domain,
                    'expiry_date': None,
                    'days_remaining': None,
                    'error': error
                }
    
    def spinner_updater():
        """Update spinner positions for pending domains"""
        while any(domain_status[d]['status'] == 'pending' for d in domains):
            for domain in domains:
                if domain_status[domain]['status'] == 'pending':
                    domain_status[domain]['spinner_pos'] += 1
            update_display()
            time.sleep(0.1)
    
    print(f"{Colors.CYAN}🚀 Starting certificate checks...{Colors.END}")
    print()  # Add space for the status display
    
    # Start spinner updater thread
    spinner_thread = Thread(target=spinner_updater, daemon=True)
    spinner_thread.start()
    
    # Initial display showing all domains
    update_display()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_domain = {executor.submit(check_domain, domain): domain for domain in domains}
        
        for future in concurrent.futures.as_completed(future_to_domain):
            result = future.result()
            results.append(result)
    
    # Clear the status display
    with display_lock:
        # Move cursor up and clear the display area
        if hasattr(update_display, 'lines_printed'):
            for _ in range(update_display.lines_printed):
                print(f"\033[1A\033[2K", end="")  # Move up one line and clear it
    
    print("\n" + "═" * 80)
    print(f"{Colors.BOLD}{Colors.BLUE}📊 RESULTS{Colors.END}")
    print("═" * 80)
    
    valid_count = expired_count = warning_count = error_count = 0
    
    # Sort results by days remaining (errors last)
    results.sort(key=lambda x: (x['error'] is not None, x['days_remaining'] if x['days_remaining'] is not None else -999))
    
    for result in results:
        domain = result['domain']
        if result['error']:
            print(f"{Colors.RED}❌ {domain:30}{Colors.END} {Colors.RED}ERROR{Colors.END:20} {result['error'][:50]}")
            error_count += 1
        else:
            days_remaining = result['days_remaining']
            expiry_date = result['expiry_date']
            
            if days_remaining <= 0:
                status_color = Colors.RED
                status_icon = "🔴"
                status_text = "EXPIRED"
                expired_count += 1
            elif days_remaining <= args.threshold:
                status_color = Colors.YELLOW
                status_icon = "🟡"
                status_text = "EXPIRING SOON"
                warning_count += 1
            else:
                status_color = Colors.GREEN
                status_icon = "🟢"
                status_text = "VALID"
                valid_count += 1
            
            print(f"{status_icon} {domain:30} {status_color}{status_text:15}{Colors.END} Expires: {expiry_date} ({days_remaining} days)")
    
    print("═" * 80)
    
    # Calculate percentages
    total = len(domains)
    valid_pct = (valid_count / total * 100) if total > 0 else 0
    warning_pct = (warning_count / total * 100) if total > 0 else 0
    expired_pct = (expired_count / total * 100) if total > 0 else 0
    error_pct = (error_count / total * 100) if total > 0 else 0
    
    print(f"{Colors.BOLD}{Colors.CYAN}📊 CERTIFICATE HEALTH SUMMARY{Colors.END}")
    print("═" * 80)
    
    # Status bars
    def create_status_bar(count, total, color):
        if total == 0:
            return ""
        bar_length = 40
        filled_length = int(bar_length * count / total)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        return f"{color}[{bar}]{Colors.END}"
    
    if valid_count > 0:
        bar = create_status_bar(valid_count, total, Colors.GREEN)
        print(f"{Colors.GREEN}🟢 VALID CERTIFICATES{Colors.END:30}    {valid_count:3d} / {total:<3d} ({valid_pct:5.1f}%)")
        print(f"   {bar}")
        print()
    
    if warning_count > 0:
        bar = create_status_bar(warning_count, total, Colors.YELLOW)
        print(f"{Colors.YELLOW}🟡 EXPIRING SOON{Colors.END:30}         {warning_count:3d} / {total:<3d} ({warning_pct:5.1f}%)")
        print(f"   {bar}")
        print()
    
    if expired_count > 0:
        bar = create_status_bar(expired_count, total, Colors.RED)
        print(f"{Colors.RED}🔴 EXPIRED CERTIFICATES{Colors.END:30}   {expired_count:3d} / {total:<3d} ({expired_pct:5.1f}%)")
        print(f"   {bar}")
        print()
    
    if error_count > 0:
        bar = create_status_bar(error_count, total, Colors.RED)
        print(f"{Colors.RED}❌ CONNECTION ERRORS{Colors.END:30}      {error_count:3d} / {total:<3d} ({error_pct:5.1f}%)")
        print(f"   {bar}")
        print()
    
    # Overall health indicator
    if expired_count > 0 or error_count > 0:
        health_status = f"{Colors.RED}🚨 ATTENTION REQUIRED{Colors.END}"
    elif warning_count > 0:
        health_status = f"{Colors.YELLOW}⚠️  MONITORING NEEDED{Colors.END}"
    else:
        health_status = f"{Colors.GREEN}✅ ALL CERTIFICATES HEALTHY{Colors.END}"
    
    print("─" * 80)
    print(f"{Colors.BOLD}OVERALL STATUS: {health_status}{Colors.END}")
    print("═" * 80)

if __name__ == "__main__":
    main()

