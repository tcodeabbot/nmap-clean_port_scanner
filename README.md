
# Network Port Scanning Tool

## Overview
This Network Port Scanning Tool is a Python-based application designed to scan a target IP address for open ports and gather version information about the services running on those ports. Additionally, it checks for anonymous FTP access and attempts to upload a sample file if such access is allowed. This tool leverages the `nmap` and `ftplib` libraries to perform comprehensive network assessments.

## Features
- **Port Scanning**: Identifies open ports on the target IP and gathers detailed service information.
- **Service Version Detection**: Provides version details for detected services, aiding in vulnerability assessments.
- **FTP Anonymous Access Check**: Tests if anonymous FTP access is permitted and uploads a sample file to verify access.

## Importance in Network Assessments
Understanding open ports and the services running on them is crucial for network security assessments. This tool helps in:
- Identifying potential vulnerabilities associated with open ports and outdated services.
- Verifying network configurations and firewall rules.
- Detecting unauthorized services that may pose security risks.
- Assessing FTP server security by testing anonymous access, which can be a significant security concern if misconfigured.

## Prerequisites
Ensure you have the following libraries installed:
- `nmap`
- `ftplib`

You can install `nmap` using pip:
```sh
pip install python-nmap
```

## Installation
Clone this repository to your local machine:
```sh
git clone <repository-url>
cd <repository-directory>
```

## Usage
Run the script and provide the target IP address when prompted:
```sh
python port_scanner.py
```

### Example Output
```sh
$ python port_scanner.py
Enter the target IP: 192.168.1.1
Scan report for 192.168.1.1:
Open Ports:
  - Port 21/tcp: open (ftp)
  - Port 80/tcp: open (http)
  - Port 443/tcp: open (https)

Version Information:
  - Port 21: ftp vsftpd 3.0.3
  - Port 80: http Apache httpd 2.4.41
  - Port 443: https OpenSSL 1.1.1

Checking for anonymous FTP access...
Anonymous FTP access allowed. Sample file uploaded.
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome! Please read the [CONTRIBUTING](CONTRIBUTING.md) guidelines before submitting a pull request or contact me at tabiex.sec@gmail.com

## Acknowledgements
Special thanks to the developers and maintainers of the `nmap` and `ftplib` libraries.
