#!/usr/bin/env python3
import os
import sys
import re
import json
import time
import subprocess
import argparse
import shutil
import tempfile
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich import print as rprint

# --- GLOBALS & CONFIG ---
VERSION = "2.0.0"
console = Console()
_output_lock = threading.Lock()
_hosts_lock = threading.Lock()

results = {
    "ip": "",
    "ports": {},
    "hostnames": set(),
    "directories": set(),
    "subdomains": set(),
    "start_time": None,
    "all_output": []  # List for O(n) collection instead of O(n²) string concat
}

# Runtime config set from args
_config = {
    "domain_suffix": ".htb",
    "no_hosts_update": False,
}

def run_command(cmd, timeout=600):
    """Run a command and return (stdout, stderr, returncode). Thread-safe."""
    try:
        is_shell = isinstance(cmd, str)
        process = subprocess.run(
            cmd, shell=is_shell, capture_output=True, text=True, timeout=timeout
        )
        with _output_lock:
            results['all_output'].append(process.stdout)
            results['all_output'].append(process.stderr)
        return process.stdout, process.stderr, process.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as e:
        return "", str(e), 1

def _get_all_output():
    """Join collected output chunks. Called once for greedy extraction."""
    with _output_lock:
        return "\n".join(results['all_output'])

def check_root():
    if os.geteuid() != 0:
        rprint("[bold red][!] Root privileges required. Run with sudo.[/bold red]")
        sys.exit(1)

def check_dependencies():
    """Check for required and optional tools at startup."""
    required = ["nmap"]
    optional = {
        "rustscan": "faster port scanning (falls back to nmap)",
        "ffuf": "vhost & directory fuzzing (Phase 3 & 4)",
        "gobuster": "DNS subdomain enumeration (Phase 3)",
        "curl": "HTTP banner probing (Phase 2)",
        "dig": "PTR DNS lookups (Phase 2)",
        "openssl": "SSL certificate extraction (Phase 2)",
    }

    missing_req = [t for t in required if not shutil.which(t)]
    if missing_req:
        rprint(f"[bold red][!] Required tools missing: {', '.join(missing_req)}[/bold red]")
        rprint("[bold red]    Install them and try again.[/bold red]")
        sys.exit(1)

    missing_opt = {t: d for t, d in optional.items() if not shutil.which(t)}
    for tool, desc in missing_opt.items():
        rprint(f"[yellow][!] Optional: {tool} not found — {desc} will be skipped[/yellow]")

def print_step(phase, text):
    rprint(f"\n[bold cyan]● {phase}: {text}[/bold cyan]")

def preflight_check(ip):
    out, _, code = run_command(["ping", "-c", "1", "-W", "2", ip])
    if code == 0: return True
    out_nmap, _, _ = run_command(["nmap", "-Pn", "-p22,80,443", "--min-rate", "1000", ip])
    if "open" in out_nmap: return True
    rprint("[bold red][!] Target appears down. Check VPN.[/bold red]")
    return False

def _build_hostname_regex():
    """Build regex from configured domain suffix(es). e.g. '.htb' -> r'([\\w\\-]+\\.htb)'"""
    suffixes = [s.strip().lstrip(".") for s in _config['domain_suffix'].split(",") if s.strip()]
    if not suffixes:
        suffixes = ["htb"]
    parts = "|".join(re.escape(s) for s in suffixes)
    return rf"([\w\-]+\.(?:{parts}))"

# --- PHASE 1: PORT SCAN ---
def phase_port_scan(ip, rate=1000):
    print_step("PHASE 1", "PORT SCANNING")
    found_ports = set()

    # Fast Discovery
    if shutil.which("rustscan"):
        with console.status("[yellow]Rustscanning...[/yellow]"):
            out, _, _ = run_command(["rustscan", "-a", ip, "-r", "1-65535", "--ulimit", "5000", "--", "-Pn"])
            found_ports.update(re.findall(r"Open \d+\.\d+\.\d+\.\d+:(\d+)", out))

    if not found_ports:
        with console.status("[yellow]Nmapping...[/yellow]"):
            out, _, _ = run_command(["nmap", "-sS", "-p-", "-T4", "--min-rate", str(rate),
                                     "--max-retries", "2", "--open", "-Pn", ip])
            found_ports.update(re.findall(r"(\d+)/tcp\s+open", out))

    if not found_ports:
        rprint("[red][!] No ports found.[/red]")
        return

    # Initialize results
    for p in found_ports:
        results['ports'][p] = {"proto": "tcp", "state": "open", "service": "unknown", "version": "", "notes": []}

    # Detailed Inspection
    with console.status("[yellow]Inspecting services...[/yellow]"):
        port_list = ",".join(sorted(list(found_ports), key=int))
        out_detail, _, _ = run_command(["nmap", "-sVC", "-T4", "--max-retries", "2",
                                        f"-p{port_list}", "-Pn", ip])

        current_port = None
        for line in out_detail.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$", line)
            if m:
                p, proto, state, svc, ver = m.groups()
                current_port = p
                if p not in results['ports']:
                    results['ports'][p] = {"notes": []}
                results['ports'][p].update({"proto": proto, "state": state, "service": svc, "version": ver.strip()})
            elif current_port and (line.startswith("|") or line.startswith("_") or line.startswith(" ") or line.startswith("\t")):
                results['ports'][current_port]['notes'].append(line.rstrip())

    # Output Table (4-Column Layout, Raw string formatting to prevent markup mangling/swallowing)
    console.print(f"\n{'PORT':<10} {'SERVICE':<15} {'VERSION':<35} {'NOTES'}", style="bold")
    console.print("-" * 100)
    for p in sorted(results['ports'].keys(), key=int):
        res = results['ports'][p]
        port_str = f"{p}/{res['proto']}"
        svc_str = res['service']
        ver_str = res['version'][:34]

        notes = res.get('notes', [])
        if not notes:
            console.print(f"{port_str:<10} {svc_str:<15} {ver_str:<35}", markup=False, highlight=False)
            continue

        # First line of notes aligns with the port string
        console.print(f"{port_str:<10} {svc_str:<15} {ver_str:<35} {notes[0].strip()}", markup=False, highlight=False)
        # Subsequent lines align neatly under the NOTES column
        for note in notes[1:]:
            console.print(f"{'':<10} {'':<15} {'':<35} {note.strip()}", markup=False, highlight=False)

# --- PHASE 2: HOSTNAME RESOLUTION ---
def is_valid_hostname(h):
    if not h: return False
    h = h.strip().lower().rstrip(".")
    if any(x in h for x in [";", "#", "<", "!", " ", ":", "\\", "/"]): return False
    if h in ["localhost", "kali", "target", "options", "dig", "host"]: return False
    return len(h) > 2

def update_hosts(ip, hostname):
    """Thread-safe hostname registration and /etc/hosts update."""
    if not is_valid_hostname(hostname): return
    hostname = hostname.strip().lower().rstrip(".")

    with _hosts_lock:
        if hostname in results['hostnames']: return

        if not _config['no_hosts_update']:
            try:
                with open("/etc/hosts", "r") as f: content = f.read()
                if re.search(rf"^{re.escape(ip)}\s+.*\b{re.escape(hostname)}\b", content, re.MULTILINE):
                    results['hostnames'].add(hostname); return
                with open("/etc/hosts", "a") as f: f.write(f"\n{ip}  {hostname}")
                rprint(f"[green][+] Host added:[/green] {hostname}")
            except Exception:
                pass  # /etc/hosts not writable — still track the hostname

        results['hostnames'].add(hostname)

def _probe_web_port(ip, p):
    """Probe a single web port for hostnames via HTTP headers and page title. Thread-safe."""
    if not shutil.which("curl"):
        return []

    found = []
    hostname_re = _build_hostname_regex()
    proto = "https" if p in ['443', '8443'] else "http"
    url = f"{proto}://{ip}:{p}"

    # Check redirect Location header
    out_i, _, _ = run_command(["curl", "-sk", "-I", "--max-time", "5", "--connect-timeout", "3", url])
    loc = re.search(r"Location: (.*)", out_i, re.IGNORECASE)
    if loc:
        m = re.search(r"https?://([^:/]+)", loc.group(1))
        if m and m.group(1) != ip: found.append(m.group(1))

    # Check page title
    # Use shell pipe for head -c to guarantee memory safety if target serves a massive file
    out_b, _, _ = run_command(f"curl -sk --max-time 5 --connect-timeout 3 {url} | head -c 5000")
    title = re.search(r"<title>(.*?)</title>", out_b, re.IGNORECASE | re.DOTALL)
    if title:
        found.extend(re.findall(hostname_re, title.group(1), re.IGNORECASE))

    return found

def _extract_ssl_hostnames(ip, p):
    """Extract hostnames from SSL certificate on a given port. Thread-safe."""
    if not shutil.which("openssl"):
        return []

    found = []
    try:
        p1 = subprocess.Popen(["openssl", "s_client", "-connect", f"{ip}:{p}"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
        p2 = subprocess.Popen(["openssl", "x509", "-noout", "-text"],
                               stdin=p1.stdout, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
        p1.stdout.close()
        out, _ = p2.communicate(timeout=10)

        with _output_lock:
            results['all_output'].append(out)

        for h in re.findall(r"DNS:([^,\s]+)", out):
            found.append(h)
        cn = re.search(r"Subject:.*?CN\s*=\s*([^,\s/]+)", out)
        if cn:
            found.append(cn.group(1))
    except Exception:
        pass

    return found

def phase_hostname_resolution(ip):
    print_step("PHASE 2", "HOSTNAME DISCOVERY")
    hostname_re = _build_hostname_regex()

    # 1. PTR lookup
    if shutil.which("dig"):
        out, _, _ = run_command(["dig", "-x", ip, "+short"])
        for line in out.splitlines(): update_hosts(ip, line)
    else:
        rprint("[yellow]  [!] dig not found, skipping PTR lookup[/yellow]")

    # 2. HTTP Banner/Title - Check ALL likely web ports CONCURRENTLY
    potential_web = set(['80', '443', '8080', '8000', '8443', '8888'])
    for p, info in results['ports'].items():
        if 'http' in info['service'] or 'ssl' in info['service']: potential_web.add(p)

    active_web_ports = [p for p in potential_web if p in results['ports']]

    if active_web_ports:
        with ThreadPoolExecutor(max_workers=min(8, len(active_web_ports))) as executor:
            futures = {executor.submit(_probe_web_port, ip, p): p for p in active_web_ports}
            for future in as_completed(futures):
                try:
                    for hostname in future.result():
                        update_hosts(ip, hostname)
                except Exception:
                    pass

    # 3. SSL cert extraction — CONCURRENT across all SSL ports
    ssl_ports = [p for p, info in results['ports'].items()
                 if p in ['443', '8443'] or 'ssl' in info['service']]

    if ssl_ports:
        with ThreadPoolExecutor(max_workers=min(4, len(ssl_ports))) as executor:
            futures = {executor.submit(_extract_ssl_hostnames, ip, p): p for p in ssl_ports}
            for future in as_completed(futures):
                try:
                    for hostname in future.result():
                        update_hosts(ip, hostname)
                except Exception:
                    pass

    # 4. Greedy Extraction from all collected output
    all_output = _get_all_output()
    for h in re.findall(hostname_re, all_output, re.IGNORECASE):
        update_hosts(ip, h)

    if results['hostnames']:
        for h in sorted(results['hostnames']): rprint(f"[green][+] Discovered Host:[/green] {h}")
    else:
        rprint("[yellow][!] No hostnames found. Try <name>.htb if that matches the lab name.[/yellow]")

# --- PHASE 3: SUBDOMAIN ---
def _run_vhost_fuzz(ip, domain, p, wordlist, threads):
    """Run ffuf vhost fuzzing on a single port. Returns list of discovered subdomains."""
    found = []
    proto = "https" if p in ['443', '8443'] else "http"
    cmd = ["ffuf", "-u", f"{proto}://{ip}:{p}/", "-H", f"Host: FUZZ.{domain}",
           "-w", wordlist, "-t", str(threads), "-ac", "-s"]
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as proc:
            for line in proc.stdout:
                l = line.strip()
                if l:
                    s = f"{l}.{domain}".lower()
                    found.append(s)
    except Exception:
        pass
    return found

def phase_subdomain_enum(ip, threads=50, wordlist=None, skip=False):
    if skip or not results['hostnames']: return
    print_step("PHASE 3", "SUBDOMAIN ENUMERATION")

    has_gobuster = shutil.which("gobuster")
    has_ffuf = shutil.which("ffuf")

    if not has_gobuster and not has_ffuf:
        rprint("[yellow][!] Neither gobuster nor ffuf found. Skipping subdomain enumeration.[/yellow]")
        return

    if not wordlist:
        wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if not os.path.exists(wordlist): wordlist = "/usr/share/wordlists/dirb/common.txt"

    if not os.path.exists(wordlist):
        rprint(f"[red][!] Wordlist not found: {wordlist}. Skipping subdomain enum.[/red]")
        return

    domains = set()
    for h in results['hostnames']:
        parts = h.split(".")
        if len(parts) >= 2: domains.add(".".join(parts[-2:]))

    for domain in sorted(domains):
        rprint(f"\n[*] Fuzzing {domain}...")

        # DNS enumeration with gobuster
        if has_gobuster:
            try:
                with tempfile.NamedTemporaryFile(mode='r', prefix="recon_dns_", suffix=".txt",
                                                  delete=True) as tmp:
                    run_command(["gobuster", "dns", "-d", domain, "-w", wordlist,
                                 "-t", str(threads), "-o", tmp.name, "--no-error"])
                    tmp.seek(0)
                    for line in tmp:
                        if "Found:" in line:
                            sub = line.split()[1].lower()
                            update_hosts(ip, sub)
                            rprint(f"  [green]DNS FOUND:[/green] {sub}")
            except Exception:
                pass

        # VHost fuzzing — CONCURRENT across HTTP ports
        if has_ffuf:
            http_ports = [p for p in results['ports']
                          if p in ['80', '443', '8080', '8443']
                          or 'http' in results['ports'][p]['service']]

            if http_ports:
                with ThreadPoolExecutor(max_workers=min(3, len(http_ports))) as executor:
                    futures = {executor.submit(_run_vhost_fuzz, ip, domain, p, wordlist, threads): p
                               for p in http_ports}
                    for future in as_completed(futures):
                        try:
                            for sub in future.result():
                                update_hosts(ip, sub)
                                rprint(f"  [green]VHOST FOUND:[/green] {sub}")
                        except Exception:
                            pass

# --- PHASE 4: DIRECTORY ---
def _run_dir_fuzz(url, wordlist, threads):
    """Run ffuf directory fuzzing on a single URL. Returns list of discovered paths."""
    found = []
    cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-t", str(threads),
           "-mc", "200,204,301,302,307,401,403,405", "-ac", "-s"]
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as proc:
            for line in proc.stdout:
                l = line.strip()
                if l:
                    found.append((url, l))
    except Exception:
        pass
    return found

def phase_dir_enum(ip, threads=50, wordlist=None, skip=False):
    if skip: return
    print_step("PHASE 4", "DIRECTORY ENUMERATION")

    if not shutil.which("ffuf"):
        rprint("[yellow][!] ffuf not found. Skipping directory enumeration.[/yellow]")
        return

    if not wordlist:
        wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        if not os.path.exists(wordlist): wordlist = "/usr/share/wordlists/dirb/common.txt"

    if not os.path.exists(wordlist):
        rprint(f"[red][!] Wordlist not found: {wordlist}. Skipping directory enum.[/red]")
        return

    targets = set()
    for p in results['ports']:
        if p in ['80', '443', '8080', '8443'] or 'http' in results['ports'][p]['service']:
            proto = "https" if p in ['443', '8443'] else "http"
            targets.add(f"{proto}://{ip}:{p}")
            for h in results['hostnames']: targets.add(f"{proto}://{h}:{p}")

    sorted_targets = sorted(targets)
    for url in sorted_targets:
        rprint(f"[*] Queued: {url}")

    # Run up to 3 ffuf instances concurrently — cap to avoid overwhelming target
    with ThreadPoolExecutor(max_workers=min(3, len(sorted_targets))) as executor:
        futures = {executor.submit(_run_dir_fuzz, url, wordlist, threads): url
                   for url in sorted_targets}
        for future in as_completed(futures):
            try:
                for url, path in future.result():
                    rprint(f"  [green]FOUND:[/green] {url}/[bold]{path}[/bold]")
            except Exception:
                pass

# --- MAIN ---
def main():
    check_root()

    parser = argparse.ArgumentParser(
        description=f"ReconNinja v{VERSION} — Fast reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  sudo python3 recon.py 10.10.10.1\n"
               "  sudo python3 recon.py 10.10.10.1 --no-dirs --no-subs\n"
               "  sudo python3 recon.py 10.10.10.1 --domain-suffix .htb,.local\n"
               "  sudo python3 recon.py 10.10.10.1 --no-hosts-update"
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--no-dirs", action="store_true", help="Skip directory enumeration (Phase 4)")
    parser.add_argument("--no-subs", action="store_true", help="Skip subdomain enumeration (Phase 3)")
    parser.add_argument("--no-hosts-update", action="store_true",
                        help="Don't modify /etc/hosts (hostnames are still discovered and displayed)")
    parser.add_argument("--domain-suffix", default=".htb",
                        help="Domain suffix(es) for greedy hostname extraction, comma-separated (default: .htb)")
    parser.add_argument("--threads", type=int, default=50, help="Thread count for fuzzing (default: 50)")
    parser.add_argument("--rate", type=int, default=1000, help="Nmap min packet rate (default: 1000)")
    parser.add_argument("-dw", "--dir-wordlist", help="Custom wordlist for directory fuzzing")
    parser.add_argument("-sw", "--sub-wordlist", help="Custom wordlist for subdomain enumeration")
    args = parser.parse_args()

    # Apply config
    _config['domain_suffix'] = args.domain_suffix
    _config['no_hosts_update'] = args.no_hosts_update

    results['ip'] = args.target; results['start_time'] = datetime.now()
    rprint(f"[bold cyan]RECONNINJA v{VERSION} | {args.target} | {datetime.now().strftime('%H:%M:%S')}[/bold cyan]")

    check_dependencies()

    if not preflight_check(args.target): sys.exit(1)

    phase_port_scan(args.target, rate=args.rate)
    phase_hostname_resolution(args.target)
    phase_subdomain_enum(args.target, threads=args.threads, wordlist=args.sub_wordlist, skip=args.no_subs)
    phase_dir_enum(args.target, threads=args.threads, wordlist=args.dir_wordlist, skip=args.no_dirs)

    rprint(f"\n[bold green]FINISH | DURATION: {datetime.now()-results['start_time']}[/bold green]")

if __name__ == "__main__": main()
