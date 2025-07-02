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

## 🛠️ Installation

### Super Simple Setup
```bash
# 1. Download the single file
wget https://raw.githubusercontent.com/i04n/sslcheck/main/sslcheck.py

# 2. Install the only dependency
pip install pyOpenSSL

# 3. Make it executable (optional)
chmod +x sslcheck.py

# 4. Ready to use!
python sslcheck.py --create-sample
```

### Prerequisites
- **Python 3.6+** (standard library modules included)
- **pyOpenSSL** - The only external dependency for certificate parsing
- That's it! 🎉

## 📋 Usage

### Basic Usage
```bash
# Check domains from file
python sslcheck.py -f domains.txt

# Create sample domains file
python sslcheck.py --create-sample

# Check with custom threshold (30 days)
python sslcheck.py -f domains.txt -t 30

# Check on custom port
python sslcheck.py -f domains.txt -p 8443

# Use more workers for faster processing
python sslcheck.py -f domains.txt -w 20

# Disable colors for scripting
python sslcheck.py -f domains.txt --no-color
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file` | File containing list of domains (one per line) | Required |
| `-t, --threshold` | Days threshold to consider as expiring soon | 15 |
| `-p, --port` | SSL port to check | 443 |
| `-w, --workers` | Number of concurrent workers | 10 |
| `--create-sample` | Create sample 'domains.txt' file | - |
| `--no-color` | Disable colored output | - |
| `--help` | Show help message | - |

## 📝 Domain File Format

Create a text file with one domain per line:

```
google.com
github.com
stackoverflow.com
example.com
```

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

## 🎯 Use Cases

- **DevOps Monitoring**: Monitor certificates across multiple environments
- **Security Audits**: Regular certificate expiration checks
- **Automation**: Integrate into CI/CD pipelines or cron jobs
- **Compliance**: Ensure certificates don't expire unexpectedly

---

Made with ❤️  by i04n
