import nmap
import ftplib

def scan_target(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-sV')

    report = {
        'target_ip': target_ip,
        'open_ports': [],
        'version_info': []
    }

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service_info = nm[host][proto][port]
                report['open_ports'].append({
                    'port': port,
                    'protocol': proto,
                    'state': service_info['state'],
                    'name': service_info['name']
                })
                if 'version' in service_info and service_info['version']:
                    report['version_info'].append({
                        'port': port,
                        'service': service_info['name'],
                        'version': service_info['version']
                    })

    return report

def check_ftp_anonymous(target_ip):
    try:
        ftp = ftplib.FTP(target_ip)
        ftp.login()
        ftp.cwd('/')

        sample_file_content = 'This is a sample file.'
        sample_file_name = 'sample_file.txt'
        
        with open(sample_file_name, 'w') as f:
            f.write(sample_file_content)

        with open(sample_file_name, 'rb') as f:
            ftp.storbinary(f'STOR {sample_file_name}', f)

        ftp.quit()
        return True

    except ftplib.all_errors as e:
        print(f'FTP error: {e}')
        return False

def main(target_ip):
    scan_report = scan_target(target_ip)

    print(f"Scan report for {target_ip}:")
    print("Open Ports:")
    for port_info in scan_report['open_ports']:
        print(f"  - Port {port_info['port']}/{port_info['protocol']}: {port_info['state']} ({port_info['name']})")

    print("\nVersion Information:")
    for version_info in scan_report['version_info']:
        print(f"  - Port {version_info['port']}: {version_info['service']} {version_info['version']}")

    ftp_open = any(port_info['name'] == 'ftp' for port_info in scan_report['open_ports'])
    if ftp_open:
        print("\nChecking for anonymous FTP access...")
        if check_ftp_anonymous(target_ip):
            print("Anonymous FTP access allowed. Sample file uploaded.")
        else:
            print("Anonymous FTP access not allowed or error occurred.")

if __name__ == "__main__":
    target_ip = input("Enter the target IP: ")
    main(target_ip)
