Website Scanning Tool

This is a Python-based website scanning tool that provides a variety of functionalities for analyzing websites. The tool is designed to help users gather information about a website's IP address, perform port scans, discover sub-domains, retrieve DNS records, identify web server details, gather website info via WHOIS, and check HTTP security headers. This repository contains the code and instructions for using this versatile tool.

Features

IP Address Retrieval
Extract the IP address of a given website URL.

Port Scanning
Perform a quick port scan to identify open and closed ports.
Optionally, gather service version information for the open ports.

Domain Scanner
Discover sub-domains of a given domain using a predefined list of common sub-domain names.

DNS Records Retrieval
Retrieve various DNS records such as A, AAAA, MX, NS, SOA, and TXT for a given website.

Web Server Detection
Identify the web server software running on the given website.

WHOIS Information
Gather comprehensive WHOIS information about the website's domain, including registrar details, creation and expiration dates, registrant information, and more.

HTTP Security Headers Check
Check for the presence of important HTTP security headers like Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, and others.

Usage

Clone the repository and navigate to the directory:
git clone https://github.com/lakshaykumar098/website-scanning-tool.git
cd website-scanning-tool

Install the required dependencies:
pip install -r requirements.txt

Run the tool:
python website_scanner.py

Here is a brief overview of the code:

ipAddress(url): Returns the IP address of the given URL.
portScan(url, serviceVersion=False): Performs a port scan on the given URL. If serviceVersion is True, it retrieves the version of the services running on the open ports.
progressBar(currentValue, TotalValue): Displays a progress bar in the terminal.
domainScanner(domainName): Scans for sub-domains of the given domain.
dnsRecords(url): Retrieves DNS records for the given URL.
webServer(url): Identifies the web server software of the given URL.
websiteInfo(url): Retrieves WHOIS information for the given URL.
httpSecurityHeader(url): Checks for important HTTP security headers on the given URL.

Here's an example of how to use the tool interactively:

1. IP Address
2. Port Scan
3. Domain Scanner
4. DNS Records
5. Web Server
6. Website Info
7. HTTP Security Header

Enter your Choice: 1
Enter url of the website: https://example.com
IP Address of https://example.com is 93.184.216.34

Do you wish to continue (y/n): y

Requirements
Python 3.x
Required Python packages listed in requirements.txt

Contributions
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

License
This project is licensed under the MIT License.
