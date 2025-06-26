# 🔍 SYNapse - High Performance Async Port Scanner

SYNapse is a blazing-fast, fully asynchronous port scanner built with Python. It supports modern protocol detection such as **QUIC**, **TLS**, and even basic **OS fingerprinting**. With advanced banner grabbing, concurrency control, and proxy support, SYNapse is the perfect addition to your pentest arsenal.

> 🛡️ Intended for educational and authorized security testing only.

---

## 🚀 Features

- ⚡ Asynchronous port scanning (asyncio-powered, ultra fast)
- 🔐 TLS support to detect secure services
- 🌐 QUIC protocol detection (HTTP/3 aware)
- 🔍 Banner grabbing (can be disabled)
- 🧠 OS fingerprinting (experimental)
- 🧵 Concurrency control (set how many connections at once)
- 🌍 Domain resolution (`--resolve` to convert domains to IPs)
- ⏱️ Adjustable timeout and inter-connection delay
- 📁 Output to file (`--json`, `--output`)
- 🧰 Exclude specific ports from scan
- 🌐 Proxy support (http / socks5)
- 🧪 Multiple target formats supported (IP, ranges, domains)

---

## 📦 Installation

> Requires **Python 3.8+**

```bash
git clone https://github.com/wyrexdev/SYNapse.git
cd SYNapse
pip install -r requirements.txt
```

---

## 🛠️ Basic Usage

```bash
python cli.py <target> -p <ports> [options]
```

Examples:

```bash
# Scan all ports from 1 to 1000
python cli.py anihime.com -p 1-1000

# Scan using QUIC and TLS detection
python cli.py anihime.com -p 1-1000 --quic --tls

# Disable banner grabbing
python cli.py anihime.com -p 1-1000 --no-banner

# Output to JSON file
python cli.py anihime.com -p 80,443 --json -o result.json

# Scan using SOCKS5 proxy
python cli.py anihime.com -p 1-500 --proxy socks5://127.0.0.1:9050
```

---

## 📑 Parameters Explained

**targets**  
The target or targets to scan. Can be IPs, domain names, or IP ranges.  
Examples: `127.0.0.1`, `google.com`, `192.168.1.1-192.168.1.255`

**-p, --ports**  
Required. Ports to scan. Can be single (`80`), comma-separated (`22,80,443`) or range (`1-65535`)

**-t, --timeout**  
Set timeout (in seconds) for each connection. Default is `1.0`. Higher values for slower targets.

**-c, --concurrency**  
Set maximum concurrent connections. Default is `500`. Tune according to your system.

**-v, --verbose**  
Enable verbose mode for detailed output.

**--delay**  
Set delay between connections (seconds). Useful to avoid rate limiting.

**-o, --output**  
Write scan results to a file.

**--json**  
Format output as JSON. Great for integrations.

**--no-banner**  
Disable banner grabbing. Only check if port is open.

**--tls**  
Enable TLS probing. Detects HTTPS, SMTPS, etc.

**--quic**  
Enable QUIC detection. Detects HTTP/3 and other QUIC-based services.

**--resolve**  
Resolve domain names to IP addresses before scanning.

**--os-guess**  
Enable OS fingerprinting (experimental).

**--exclude-ports**  
Comma-separated list of ports to exclude. Example: `--exclude-ports 22,80,443`

**--proxy**  
Use a proxy server. Supports HTTP and SOCKS5. Example: `--proxy socks5://127.0.0.1:9050`

---

## ✅ Example Output

```
🚀 Starting scan: 1 target(s), 1000 port(s)
🔍 QUIC Scanning: Enhanced protocol detection enabled
⚡ Concurrency: 500 | Timeout: 1.0s
🔧 Options: Delay=0.0s | Proxy=None
──────────────────────────────────────────────────
[+] anihime.com:28 OPEN | Banner: SSH-2.0-OpenSSH_9.7
[+] anihime.com:53 OPEN
[+] anihime.com:80 OPEN | Banner: HTTP/1.1 301 Moved Permanently
Server: nginx/1.27.5
Date: Thu, 26 Jun 2025 06:15:51 GMT
[+] anihime.com:143 OPEN | Banner: * OK Waiting for authentication process to respond..
[+] anihime.com:587 OPEN | Banner: 220 anihime.com ESMTP Postfix (Ubuntu)
──────────────────────────────────────────────────
✅ Scan completed in 0:00:02.179248
📊 Results: 5 open ports found
```

---

## ⚠️ Legal Notice

SYNapse is intended **only for ethical and legal use**. Always get explicit permission before scanning any target that is not under your control. The developer is **not responsible for misuse** of this tool.

---

## 💬 Final Words

SYNapse was built for those who don’t want bloated tools, prefer full control, and demand speed. It’s lightweight, readable, and extensible. Whether you're doing recon, CTFs, or internal audits — this is your hacker Swiss army knife.

> Contribute. Fork. Improve. Break things. Own networks — responsibly.  
> 🧠 Code is knowledge. Knowledge is power. Power must be wielded ethically.

---

Happy Hacking ⚡
