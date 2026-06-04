<p align="center">
  <h1 align="center">⚡ ReconNinja</h1>
  <p align="center">Fast, automated reconnaissance tool for penetration testing and CTFs.</p>
  <p align="center">
    <img src="https://img.shields.io/badge/version-2.0.0-blue" alt="Version">
    <img src="https://img.shields.io/badge/python-3.9%2B-green" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-orange" alt="License">
    <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey" alt="Platform">
  </p>
</p>

---

ReconNinja runs a full 4-phase recon pipeline against a target IP — port scanning, hostname discovery, subdomain enumeration, and directory fuzzing — in a single command. It parallelizes everything it can, auto-detects available tools, and writes discovered hostnames straight to `/etc/hosts`.

## Features

- **4-phase pipeline** — ports → hostnames → subdomains → directories
- **Concurrent scanning** — HTTP probes, SSL extraction, and fuzzing all run in parallel
- **Smart tool detection** — uses `rustscan` if available, falls back to `nmap`; skips phases gracefully if optional tools are missing
- **Auto hosts file** — discovered hostnames are written to `/etc/hosts` automatically (opt-out with `--no-hosts-update`)
- **Configurable domain matching** — defaults to `.htb`, supports any suffix via `--domain-suffix`
- **Clean output** — formatted tables and color-coded results via [Rich](https://github.com/Textualize/rich)

## Recon Phases

| Phase | What it does | Tools used |
|-------|-------------|------------|
| **1. Port Scan** | Full TCP port discovery + service/version detection | `rustscan` or `nmap` |
| **2. Hostname Discovery** | PTR lookups, HTTP redirects, page titles, SSL certs, greedy regex | `dig`, `curl`, `openssl` |
| **3. Subdomain Enumeration** | DNS brute-force + VHost fuzzing on all web ports | `gobuster`, `ffuf` |
| **4. Directory Enumeration** | Directory fuzzing on all discovered web endpoints | `ffuf` |

## Installation

### Prerequisites

**Required:**
- Python 3.9+
- [nmap](https://nmap.org/)

**Optional (recommended):**
- [rustscan](https://github.com/RustScan/RustScan) — faster port scanning
- [ffuf](https://github.com/ffuf/ffuf) — directory & vhost fuzzing
- [gobuster](https://github.com/OJ/gobuster) — DNS subdomain enumeration
- `curl`, `dig`, `openssl` — usually pre-installed on Linux/macOS

**Wordlists (recommended):**
- [SecLists](https://github.com/danielmiessler/SecLists)

### Setup

```bash
git clone https://github.com/ruwithma/reconninja.git
cd reconninja
pip install rich
```

That's it. Single file, no build step.

## Usage

```bash
# Basic full scan
sudo python3 recon.py 10.10.10.1

# Skip directory and subdomain enumeration
sudo python3 recon.py 10.10.10.1 --no-dirs --no-subs

# Use custom domain suffix (for non-HTB targets)
sudo python3 recon.py 10.10.10.1 --domain-suffix .local,.corp

# Don't touch /etc/hosts
sudo python3 recon.py 10.10.10.1 --no-hosts-update

# Custom wordlists and thread count
sudo python3 recon.py 10.10.10.1 -dw /path/to/dirs.txt -sw /path/to/subs.txt --threads 100

# Faster nmap rate (aggressive, use on stable networks)
sudo python3 recon.py 10.10.10.1 --rate 5000
```

### All Options

```
usage: recon.py [-h] [--no-dirs] [--no-subs] [--no-hosts-update]
                [--domain-suffix DOMAIN_SUFFIX] [--threads THREADS]
                [--rate RATE] [-dw DIR_WORDLIST] [-sw SUB_WORDLIST]
                target

positional arguments:
  target                Target IP address

options:
  --no-dirs             Skip directory enumeration (Phase 4)
  --no-subs             Skip subdomain enumeration (Phase 3)
  --no-hosts-update     Don't modify /etc/hosts
  --domain-suffix       Domain suffix(es) for hostname extraction,
                        comma-separated (default: .htb)
  --threads             Thread count for fuzzing (default: 50)
  --rate                Nmap min packet rate (default: 1000)
  -dw, --dir-wordlist   Custom wordlist for directory fuzzing
  -sw, --sub-wordlist   Custom wordlist for subdomain enumeration
```

## Example Output

```
RECON v2.0.0 | 10.10.10.1 | 14:30:22

● PHASE 1: PORT SCANNING
PORT       SERVICE         VERSION                             NOTES
----------------------------------------------------------------------------------------------------
22/tcp     ssh             OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
80/tcp     http            Apache httpd 2.4.52
443/tcp    ssl/http        nginx 1.18.0                        |_ssl-date: TLS randomness...

● PHASE 2: HOSTNAME DISCOVERY
[+] Host added: target.htb
[+] Host added: admin.target.htb
[+] Discovered Host: admin.target.htb
[+] Discovered Host: target.htb

● PHASE 3: SUBDOMAIN ENUMERATION
[*] Fuzzing target.htb...
  VHOST FOUND: dev.target.htb
  DNS FOUND: api.target.htb

● PHASE 4: DIRECTORY ENUMERATION
[*] Queued: http://target.htb:80
  FOUND: http://target.htb:80/admin
  FOUND: http://target.htb:80/login

FINISH | DURATION: 0:02:34.518293
```

## How It's Fast

- **Concurrent HTTP probing** — all web ports checked simultaneously (up to 8 threads)
- **Concurrent SSL extraction** — all SSL certs pulled in parallel (up to 4 threads)
- **Concurrent fuzzing** — up to 3 ffuf instances run at once
- **Nmap `-T4 --max-retries 2`** — aggressive timing with fewer retries on both scan phases
- **RustScan first** — if installed, does the initial port sweep in seconds

## Contributing

1. Fork the repo
2. Create your branch (`git checkout -b feature/something`)
3. Commit your changes (`git commit -m 'Add something'`)
4. Push to the branch (`git push origin feature/something`)
5. Open a Pull Request

### Guidelines

- Keep it a single file — that's the point
- No new dependencies beyond `rich`
- Test on Kali/Parrot before submitting
- Don't break existing flags

## License

MIT — do whatever you want with it.

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Only use it against systems you have explicit permission to test. Unauthorized scanning is illegal.
