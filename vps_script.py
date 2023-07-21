#!/usr/bin/env python3

import sys
import subprocess
import os

def get_subdomains(target, output_dir):
    if os.path.isfile(target):
        # Use amass to enumerate subdomains from a file
        amass_cmd = f"amass enum -passive -norecursive -noalts -df {target} -config amass_config.ini -o {output_dir}/amass_output.txt"
    else:
        # Use amass to enumerate subdomains from a single domain
        amass_cmd = f"amass enum -passive -norecursive -noalts -d {target} -config amass_config.ini -o {output_dir}/amass_output.txt"
    
    subfinder_cmd = f"subfinder -d {target} -all -config subfinder_config.yaml -o {output_dir}/subfinder_output.txt"
    subprocess.run(subfinder_cmd, shell=True)
    subprocess.run(amass_cmd, shell=True)

def combine_subdomains(output_dir):
    all_subdomains = set()
    subfinder_output_file = f"{output_dir}/subfinder_output.txt"
    amass_output_file = f"{output_dir}/amass_output.txt"

    with open(subfinder_output_file) as f:
        all_subdomains.update(f.read().splitlines())
    with open(amass_output_file) as f:
        all_subdomains.update(f.read().splitlines())

    sorted_subdomains = sorted(list(all_subdomains))
    with open(f"{output_dir}/sorted_subdomains.txt", "w") as f:
        f.write("\n".join(sorted_subdomains))

    return sorted_subdomains

def run_httpx_scan(subdomains, output_dir):
    httpx_cmd = f"httpx -l {output_dir}/httpx_subdomains.txt -ports 80,443 -title -o {output_dir}/httpx_output.txt"
    with open(f"{output_dir}/httpx_subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))
    subprocess.run(httpx_cmd, shell=True)

def run_rustscan(subdomains, output_dir):
    with open(f"{output_dir}/sorted_subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))

    rustscan_cmd = f"rustscan -a {output_dir}/sorted_subdomains.txt -r 1000-65000 --ulimit 10000"
    result = subprocess.check_output(rustscan_cmd, shell=True, universal_newlines=True)
    new_ports = set(map(int, result.strip().splitlines()[1:]))

    with open(f"{output_dir}/rustscan_output.txt", "w") as f:
        f.write(result)

    return new_ports

def notify_desktop(title, message):
    try:
        notify_cmd = f"notify -title '{title}' -message '{message}'"
        os.system(notify_cmd)
    except Exception as e:
        print(f"Error while sending notification: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 subdomain_port_scan.py <path_to_target_or_target_file>")
        sys.exit(1)

    target_input = sys.argv[1]
    if os.path.isfile(target_input):
        with open(target_input) as f:
            target_domains = f.read().splitlines()
    else:
        target_domains = [target_input]

    if not target_domains:
        print("Error: The target input is empty.")
        sys.exit(1)

    for target in target_domains:
        print(f"Scanning target domain: {target}")

        output_dir = f"output_{target.replace('.', '_')}"
        os.makedirs(output_dir, exist_ok=True)

        get_subdomains(target, output_dir)
        subdomains = combine_subdomains(output_dir)

        new_ports = run_rustscan(subdomains, output_dir)
        notify_desktop(f"New Subdomains and Ports Discovered for {target}",
                       f"Subdomains: {', '.join(subdomains)}\nPorts: {', '.join(map(str, new_ports))}")

        run_httpx_scan(subdomains, output_dir)

        print(f"Scan completed for target domain: {target}\n")

if __name__ == "__main__":
    main()
