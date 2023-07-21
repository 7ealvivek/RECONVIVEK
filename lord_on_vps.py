#!/usr/bin/env python3

import sys
import subprocess
import os
from tqdm import tqdm
import select

def run_command(command, desc, timeout=600):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for line in tqdm(iterable=iter(process.stdout.readline, b''), desc=desc, unit='line', ncols=100, dynamic_ncols=True):
            if process.poll() is not None:
                break
        process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        print(f"Process '{desc}' exceeded the timeout of {timeout} seconds and was terminated.")

    return process.returncode

def get_subdomains(target, output_dir):
    if os.path.isfile(target):
        # Use amass to enumerate subdomains from a file
        amass_cmd = f"amass enum -passive -norecursive -noalts -df {target} -config /home/kali/config.ini -o {output_dir}/amass_output.txt"
    else:
        # Use amass to enumerate subdomains from a single domain
        amass_cmd = f"amass enum -passive -norecursive -noalts -d {target} -config /home/kali/config.ini -o {output_dir}/amass_output.txt"
    
    subfinder_cmd = f"subfinder -d {target} -all -config /root/.config/subfinder/config.yaml -o {output_dir}/subfinder_output.txt"
    run_command(subfinder_cmd, desc="Running Subfinder")
    run_command(amass_cmd, desc="Running Amass")

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
    httpx_cmd = f"httpx -l {output_dir}/httpx_subdomains.txt -ports 80,443 -title | tee {output_dir}/httpx_output.txt"
    with open(f"{output_dir}/httpx_subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))
    subprocess.run(httpx_cmd, shell=True)

def run_rustscan(subdomains, output_dir, top_ports=True):
    with open(f"{output_dir}/sorted_subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))

    if top_ports:
        rustscan_cmd = f"rustscan -a {output_dir}/sorted_subdomains.txt --ulimit 10000 --top | tee {output_dir}/rustscan_output.txt"
    else:
        rustscan_cmd = f"rustscan -a {output_dir}/sorted_subdomains.txt -r 1000-65000 --ulimit 10000 | tee {output_dir}/rustscan_output.txt"

    result = subprocess.check_output(rustscan_cmd, shell=True, universal_newlines=True)
    new_ports = set(map(int, result.strip().splitlines()[1:]))

    return new_ports

def prompt_tool_choice(timeout=10):
    print("What tool(s) do you want to use next?\n"
          "1. httpx\n"
          "2. rustscan (Full ports)\n"
          "3. Both httpx and rustscan (Full ports)\n"
          "4. rustscan (Top ports)\n"
          "5. None (Exit)")

    rlist, _, _ = select.select([sys.stdin], [], [], timeout)
    if rlist:
        choice = sys.stdin.readline().strip()
    else:
        print(f"No response in {timeout} seconds. Auto-selecting option 5 (None/Exit).")
        choice = '5'

    if choice in ('1', '2', '3', '4', '5'):
        return choice
    else:
        print("Invalid choice. Please choose again.\n")

def send_notification(title, message):
    notification_cmd = f"notify -title '{title}' -message '{message}'"
    subprocess.run(notification_cmd, shell=True)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 Lord.py <path_to_target_or_target_file>")
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

        print(f"Subdomains sorted and saved in '{output_dir}/sorted_subdomains.txt'.")

        while True:
            choice = prompt_tool_choice()
            if choice == '1':
                run_httpx_scan(subdomains, output_dir)
            elif choice == '2':
                run_rustscan(subdomains, output_dir, top_ports=False)
            elif choice == '3':
                run_httpx_scan(subdomains, output_dir)
                run_rustscan(subdomains, output_dir, top_ports=False)
            elif choice == '4':
                new_ports = run_rustscan(subdomains, output_dir, top_ports=True)
                send_notification("New Ports Discovered", f"New open ports discovered: {', '.join(map(str, new_ports))}")
            elif choice == '5':
                print("Exiting.")
                sys.exit(0)
            else:
                print("Invalid choice. Please choose again.\n")

        print(f"Scan completed for target domain: {target}\n")

if __name__ == "__main__":
    main()
