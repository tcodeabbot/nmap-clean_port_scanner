# nmap-clean_port_scanner

## Overview

This Python tool scans a target IP address for open ports using Nmap, organizes the output of the open ports along with their versions, and checks if FTP is open. If anonymous FTP login is allowed, it uploads a sample file to the user's directory.

## Features

- Scans all ports of a target IP using Nmap.
- Provides an organized output of open ports and their versions.
- Checks if FTP (port 21) is open.
- If FTP is open and anonymous login is allowed, uploads a sample file to the `/users/` directory.

## Prerequisites

- Python 3.x
- `python-nmap` library
- `ftplib` library (comes with Python standard library)

## Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/yourusername/nmap-ftp-tool.git
    cd nmap-ftp-tool
    ```

2. **Install Required Python Libraries:**
    ```bash
    pip install python-nmap
    ```

## Usage

1. Run the Tool:**
    ```bash
    python scanner.py <target_ip_address>
    ```
    Replace `<target_ip_address>` with the IP address you want to scan.

## Example

```bash
python scanner.py 192.168.1.100
```

## Detailed Output

- **Open Ports and Versions:**
  The tool will print the open ports and their respective versions in an organized manner.

- **FTP Interaction:**
  If the FTP port (21) is open and allows anonymous login, the tool will create a sample file named `sample_file.txt` and upload it to the `/users/` directory.

## Script Explanation

### `scanner.py`

```python
import nmap
import ftplib
import argparse

def scan_target(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-p- -sV')  # Scan all ports and get version info

    open_ports = []
    versions = {}

    # Organize open ports and their versions
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
                    versions[port] = nm[host][proto][port]['version']

    # Print organized output of open ports and their versions
    print(f"Open ports on {ip_address}:")
    for port in open_ports:
        print(f"    Port {port}: {versions[port]}")

    # Check for FTP and handle anonymous login
    if 21 in open_ports:
        try:
            ftp = ftplib.FTP(ip_address)
            ftp.login("anonymous", "guest@example.com")
            print("\nFTP anonymous login successful.")
            filename = "sample_file.txt"
            with open(filename, 'w') as file:
                file.write("This is a sample file created by the script.")
            ftp.storbinary(f"STOR /users/{filename}", open(filename, 'rb'))
            print(f"Sample file '{filename}' uploaded to /users/ directory.")
            ftp.quit()
        except Exception as e:
            print(f"FTP error: {str(e)}")
    else:
        print("\nFTP port (21) is not open or not found.")

def main():
    parser = argparse.ArgumentParser(description="Scan a target IP for open ports, version info, and interact with FTP.")
    parser.add_argument("ip_address", type=str, help="Target IP address to scan")
    args = parser.parse_args()

    scan_target(args.ip_address)

if __name__ == "__main__":
    main()
```

## Contribution

If you want to contribute to this project, please fork the repository and create a pull request with your changes. Ensure your code adheres to the project's coding standards and passes all tests.


## Contact

For any questions or issues, please open an issue on this repository or contact [yourname](mailto:tabiex.sec@gmail.com).

