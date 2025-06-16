# Imports
import nmap
import argparse

# Scan Target
def scan_target(target, ports):
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {target} on ports {ports}...")
    scanner.scan(hosts = target, ports = ports, arguments = '-sV')
    
    hosts = scanner.all_hosts()
    for host in hosts:
        print(f"\n[+] Scan results for {host}")
        protocols = scanner[host].all_protocols()
        for protocol in protocols:
            ports = sorted(scanner[host][protocol].keys())
            for port in ports:
                state = scanner[host][protocol][port]["state"]
                name = scanner[host][protocol][port]["name"]
                print(f"Port {port}/{protocol} - {state.upper()} - {name}")
                
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "NetVuS - Network Vulnerability Scanner")
    parser.add_argument("--target", required = True, help = "Target IP or hostname")
    parser.add_argument("--ports", default = "20-1024", help = "Port range to scan (default: 20-1024)")
    args = parser.parse_args()
    
    scan_target(args.target, args.ports)
    
# Example usage:
# python netvus.py --target <target_ip> 
# python netvus.py --target <target_ip> --ports <port_range>