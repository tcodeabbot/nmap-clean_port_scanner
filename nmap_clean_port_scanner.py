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
    parser = argparse.ArgumentParser(
        description="Scan a target IP for open ports, version info, and interact with FTP.")
    parser.add_argument("ip_address", type=str, help="Target IP address to scan")
    args = parser.parse_args()

    scan_target(args.ip_address)


if __name__ == "__main__":
    main()
