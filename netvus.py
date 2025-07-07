# Imports
import nmap
import argparse

# Banner
def print_banner():
    banner = r"""

_____   __    ________    __              
___  | / /______  /__ |  / /___  _________
__   |/ /_  _ \  __/_ | / /_  / / /_  ___/
_  /|  / /  __/ /_ __ |/ / / /_/ /_(__  ) 
/_/ |_/  \___/\__/ _____/  \__,_/ /____/    v2.0

NetVuS - Network Vulnerability Scanner
"""
    print(banner)

# Scan Target
def scan_target(target, ports, os_detect=False, default_scripts=False):
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {target} on ports {ports}...")

    # Nmap arguments
    nmap_args = '-sV'
    if os_detect:
        nmap_args += ' -O'
    if default_scripts:
        nmap_args += ' -sC'

    try:
        scanner.scan(hosts=target, ports=ports, arguments=nmap_args)
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        return

    hosts = scanner.all_hosts()
    if not hosts:
        print("[!] No hosts found or host is down.")
        return

    for host in hosts:
        print(f"\n[+] Scan results for {host}")
        print(f"Hostname: {scanner[host].hostname()}")
        print(f"State: {scanner[host].state()}")

        # Show open ports
        protocols = scanner[host].all_protocols()
        for protocol in protocols:
            ports = sorted(scanner[host][protocol].keys())
            print(f"\n--- {protocol.upper()} Ports ---")
            print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}")
            print("-" * 35)
            for port in ports:
                state = scanner[host][protocol][port]["state"]
                name = scanner[host][protocol][port]["name"]
                print(f"{port}/{protocol:<8}{state.upper():<10}{name:<15}")

        # Show OS detection results
        if os_detect and 'osmatch' in scanner[host]:
            print("\n--- OS Detection ---")
            for os in scanner[host]['osmatch']:
                print(f"OS: {os['name']} (Accuracy: {os['accuracy']}%)")
                break 

if __name__ == "__main__":
    print_banner()
    
    parser = argparse.ArgumentParser(description="NetVuS - Network Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--ports", default="20-1024", help="Port range to scan (default: 20-1024)")
    parser.add_argument("--os-detect", action="store_true", help="Enable OS detection (-O)")
    parser.add_argument("--default-scripts", action="store_true", help="Use Nmap's default scripts (-sC)")
    args = parser.parse_args()

    scan_target(args.target, args.ports, args.os_detect, args.default_scripts)