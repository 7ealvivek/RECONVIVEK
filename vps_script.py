#!/usr/bin/env python3

import sys
import subprocess
import os

def get_subdomains(target):
    subfinder_cmd = f"subfinder -d {target} -all -config subfinder_config.yaml -o subfinder_output.txt"
    amass_cmd = f"amass enum -passive -norecursive -noalts -d {target} -config amass_config.ini -o amass_output.txt"
    subprocess.run(subfinder_cmd, shell=True)
    subprocess.run(amass_cmd, shell=True)

def combine_subdomains():
    all_subdomains = set()
    with open("subfinder_output.txt") as f:
        all_subdomains.update(f.read().splitlines())
    with open("amass_output.txt") as f:
        all_subdomains.update(f.read().splitlines())
    return sorted(list(all_subdomains))

def run_httpx_scan(subdomains):
    httpx_cmd = f"httpx -l httpx_subdomains.txt -ports 80,443 -title -o httpx_output.txt"
    with open("httpx_subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))
    subprocess.run(httpx_cmd, shell=True)

def run_rustscan(subdomains):
    new_ports = set()
    with open("sorted_subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))

    rustscan_cmd = f"rustscan -a sorted_subdomains.txt -r 1000-65000 --ulimit 10000"
    result = subprocess.check_output(rustscan_cmd, shell=True, universal_newlines=True)
    new_ports.update(set(map(int, result.strip().splitlines()[1:])))
    return new_ports

def notify_new_subdomain_and_ports(subdomains, new_ports):
    if os.path.isfile("previous_subdomains.txt"):
        with open("previous_subdomains.txt") as f:
            previous_subdomains = set(f.read().splitlines())
    else:
        previous_subdomains = set()

    new_subdomains = set(subdomains) - previous_subdomains

    if new_subdomains:
        for subdomain in new_subdomains:
            # Use the 'notify' tool to send a separate notification for each new subdomain
            notify_cmd = f"notify -title 'New Subdomain Discovered' -message '{subdomain}'"
            os.system(notify_cmd)

    if new_ports:
        # Use the 'notify' tool to send a notification for new open ports
        notify_cmd = f"notify -title 'New Open Ports Discovered' -message 'New open ports: {', '.join(map(str, new_ports))}'"
        os.system(notify_cmd)

    with open("previous_subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 subdomain_port_scan.py <path_to_target_file>")
        sys.exit(1)

    target_file = sys.argv[1]
    if not os.path.isfile(target_file):
        print(f"Error: The target file '{target_file}' does not exist.")
        sys.exit(1)

    with open(target_file) as f:
        target_domains = f.read().splitlines()

    if not target_domains:
        print("Error: The target file is empty.")
        sys.exit(1)

    for target in target_domains:
        print(f"Scanning target domain: {target}")

        get_subdomains(target)
        subdomains = combine_subdomains()

        new_ports = run_rustscan(subdomains)
        notify_new_subdomain_and_ports(subdomains, new_ports)

        run_httpx_scan(subdomains)

        print(f"Scan completed for target domain: {target}\n")

if __name__ == "__main__":
    main()
