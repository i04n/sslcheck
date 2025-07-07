# 🔒 SSL Certificate Checker

A modern, colorful command-line tool to monitor SSL certificate expiration for multiple domains with concurrent checking and beautiful output.

## 🚀 **Single-File Simplicity**

- **📁 One file only** - Everything in a single `sslcheck.py` script
- **📦 Minimal dependencies** - Only requires `pyOpenSSL` (plus Python standard library)
- **⚡ Zero configuration** - Works out of the box
- **🔧 Easy deployment** - Just copy the file and run!

## ✨ Features

- 🚀 **Concurrent Processing** - Check multiple domains simultaneously for faster results
- 🎨 **Colorful Output** - Beautiful terminal output with colors and emojis
- 📊 **Progress Indicators** - Real-time progress bar during certificate checks
- ⚙️ **Configurable** - Customizable expiration thresholds and ports
- 📝 **Detailed Reporting** - Comprehensive summary with statistics
- 🔧 **Error Handling** - Robust error handling with clear error messages
- 📄 **Sample Generator** - Built-in sample domains file generator
- 🔧 **Configuration Files** - Support for `sslcheck.conf` configuration files
- 📝 **Logging Support** - Built-in logging for cron job integration
- 🖥️ **Multiple Input Methods** - Command line domains, files, or configuration

## 🛠️ Installation

### Super Simple Setup
```bash
# 1. Download the single file
wget https://raw.githubusercontent.com/i04n/sslcheck/main/sslcheck.py

# 2. Install the only dependency
pip install pyOpenSSL

# 3. Rename and make it executable
mv sslcheck.py sslcheck
chmod +x sslcheck

# 4. Ready to use!
./sslcheck --create-sample

# 5. (Optional) Move to PATH for global access
sudo mv sslcheck /usr/local/bin/
sslcheck --help
```

### Prerequisites
- **Python 3.6+** (standard library modules included)
- **pyOpenSSL** - The only external dependency for certificate parsing
- That's it! 🎉

## 📋 Usage

### Basic Usage Examples

#### Quick Domain Check
```bash
# Check a single domain
sslcheck -d example.com

# Check multiple domains
sslcheck -d example.com google.com github.com
```

#### File-Based Checking
```bash
# Check domains from file
sslcheck -f domains.txt

# Create sample domains file first
sslcheck --create-sample
sslcheck -f domains.txt
```

#### Configuration File Usage
```bash
# Use automatic configuration (searches for sslcheck.conf)
sslcheck

# Use custom configuration file
sslcheck -c /path/to/my-config.conf
```

#### Advanced Options
```bash
# Custom threshold (30 days warning)
sslcheck -d example.com -a 30

# Check on custom port
sslcheck -f domains.txt -p 8443

# Use more workers for faster processing
sslcheck -f domains.txt -w 20

# Disable colors for scripting
sslcheck -f domains.txt --no-color

# Enable logging for cron jobs
sslcheck -d example.com --log-file /var/log/sslcheck.log
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file` | File containing list of domains (one per line) | Optional |
| `-d, --domains` | List of domains to check (space-separated) | Optional |
| `-c, --config` | Custom configuration file path | Optional |
| `-t, --threshold` | Days threshold to consider as expiring soon | 15 |
| `-a, --alert` | Alias for --threshold (days before expiration to alert) | 15 |
| `-p, --port` | SSL port to check | 443 |
| `-w, --workers` | Number of concurrent workers | 10 |
| `--log-file` | Log file path for cron job integration | Optional |
| `--create-sample` | Create sample 'domains.txt' file | - |
| `--no-color` | Disable colored output | - |
| `--help` | Show help message | - |

## 📝 Input Methods

### 1. Command Line Domains
```bash
# Check specific domains directly
python sslcheck.py -d example.com google.com github.com
```

### 2. Domain File Format
Create a text file with one domain per line:

```
google.com
github.com
stackoverflow.com
example.com
```

### 3. Configuration File
Create a `sslcheck.conf` file in your home directory or current directory:

```ini
[DEFAULT]
# Default domains to check (comma-separated)
domains = example.com, google.com, github.com

# Days before expiration to trigger alerts
alert_days = 30

# Default port to check (optional, default is 443)
# port = 443

# Number of concurrent workers (optional, default is 10)
# workers = 10
```

#### Configuration Priority
1. **Command line arguments** (highest priority)
2. **Files specified with -f, --file**
3. **Configuration file** (lowest priority)

#### Configuration File Locations
The tool automatically searches for configuration files in this order:
- Custom file specified with `-c, --config`
- `~/sslcheck.conf` (home directory)
- `./sslcheck.conf` (current directory)

## 🎨 Output Examples

### Successful Check
```
🔒 SSL Certificate Checker
📋 Checking 5 domain(s) on port 443
⚠️  Warning threshold: 15 days
👥 Using 10 concurrent workers
════════════════════════════════════════════════════════════════════════════════
🚀 Starting certificate checks...
Progress: [████████████████████████████████████████] 100.0% (5/5)
════════════════════════════════════════════════════════════════════════════════
📊 RESULTS
════════════════════════════════════════════════════════════════════════════════
🟢 google.com                     VALID           Expires: 2024-03-15 (89 days)
🟡 example.com                    EXPIRING SOON   Expires: 2024-01-20 (10 days)
🔴 expired.badssl.com             EXPIRED         Expires: 2023-12-01 (-25 days)
❌ nonexistent.domain.com         ERROR           [Errno -5] No address associated with hostname
════════════════════════════════════════════════════════════════════════════════
📈 SUMMARY
🟢 Valid: 1
🟡 Expiring Soon: 1
🔴 Expired: 1
❌ Errors: 1
════════════════════════════════════════════════════════════════════════════════
```

## 🚀 Performance & Architecture

- **Concurrent Processing**: Uses ThreadPoolExecutor for parallel certificate checks
- **Configurable Workers**: Adjust the number of concurrent workers based on your needs  
- **Progress Tracking**: Real-time progress indicator shows completion status
- **Efficient Sorting**: Results are sorted by expiration status for easy review
- **Lightweight Design**: Single file with minimal footprint
- **No External Services**: Direct SSL connection testing without third-party APIs

## 🔧 Troubleshooting

### Common Issues

1. **"No address associated with hostname"**
   - The domain doesn't exist or has DNS issues
   - Check domain spelling and DNS resolution

2. **Connection timeouts**
   - Domain might be blocking connections
   - Try reducing the number of workers with `-w`

3. **SSL errors**
   - Certificate might be invalid or self-signed
   - Port might be incorrect (try `-p 8443` for non-standard ports)

### Debugging Tips

- Use `--no-color` for cleaner output when redirecting to files
- Reduce workers (`-w 1`) to troubleshoot connection issues
- Check individual domains with minimal test files

## 📊 Exit Codes

- `0`: Success
- `1`: Error (missing file, invalid arguments, etc.)

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## 📄 License

This project is open source. Feel free to use, modify, and distribute.

## 🤖 Automation & Monitoring

### Cron Job Integration
Set up automated monitoring with cron jobs:

```bash
# Daily check at 2 AM, log to file
0 2 * * * /usr/local/bin/sslcheck -d example.com >> /var/log/sslcheck.log

# Weekly check using configuration file
0 2 * * 0 /usr/local/bin/sslcheck --log-file /var/log/sslcheck.log

# Check every 6 hours with custom threshold
0 */6 * * * /usr/local/bin/sslcheck -f /etc/domains.txt -a 30 --log-file /var/log/sslcheck.log --no-color
```

### Log Output Example
```
2025-07-07 14:57:56,584 - INFO - SSL Certificate check started for 2 domains
2025-07-07 14:57:56,584 - INFO - Domains: google.com, github.com
2025-07-07 14:57:56,584 - INFO - Port: 443, Threshold: 30 days
2025-07-07 14:57:56,656 - INFO - SSL Certificate check completed
2025-07-07 14:57:56,656 - INFO - Results: 2 valid, 0 expiring soon, 0 expired, 0 errors
2025-07-07 14:57:56,656 - INFO - google.com: Certificate valid for 64 days (expires 2025-09-09)
2025-07-07 14:57:56,656 - INFO - github.com: Certificate valid for 213 days (expires 2026-02-05)
```

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
- name: Check SSL Certificates
  run: |
    chmod +x sslcheck.py
    mv sslcheck.py sslcheck
    ./sslcheck -d ${{ vars.DOMAINS }} --no-color --log-file ssl-check.log
    cat ssl-check.log
```

## 🎯 Use Cases

- **DevOps Monitoring**: Monitor certificates across multiple environments
- **Security Audits**: Regular certificate expiration checks
- **Automation**: Integrate into CI/CD pipelines or cron jobs
- **Compliance**: Ensure certificates don't expire unexpectedly
- **Infrastructure Management**: Track certificate health across microservices
- **Alert Systems**: Integration with monitoring and alerting platforms

## 📄 License

This project is licensed under the GNU General Public License v3.0.  
Copyright (C) 2025 Juan Vassallo

---

Made with ❤️  by i04n
