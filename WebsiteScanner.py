import socket
import nmap
import validators
import itertools
import sys
import time
import threading
import requests
import ipaddress
import dns.resolver
import whois


def ipAddress(url):
    if not validators.url(url):
        return
    hostname = url.split("//")[-1].split("/")[0]
    return socket.gethostbyname(hostname)


def portScan(url, serviceVersion=False):
    processCompleted = False

    # here is the animation
    def animate():
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if processCompleted:
                break
            sys.stdout.write('\rScanning ' + c)
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r')
    threading.Thread(target=animate).start()

    def validIP():
        try:
            ipaddress.ip_address(url)
            return True
        except:
            return False

    if not validators.url(url) and not validIP():
        return
    # Get the IP address of the site
    ip_address = ipAddress(url)

    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe",]
    nm = nmap.PortScanner(nmap_search_path=nmap_path)
    if not serviceVersion:
        nm.scan(ip_address, arguments="-F")
    else:
        nm.scan(ip_address, arguments="-A")

    processCompleted = True
    time.sleep(0.1)

    open_ports = []
    closed_ports = []
    for port in nm[ip_address]['tcp'].keys():
        if nm[ip_address]['tcp'][port]['state'] == "open":
            open_ports.append(port)
        elif nm[ip_address]['tcp'][port]['state'] == "closed":
            closed_ports.append(port)

    if len(open_ports) > 0:
        print("Open ports found:")
        for port in open_ports:
            if not serviceVersion:
                print(
                    f"Port {port}: {nm[ip_address]['tcp'][port]['name']}")
            else:
                print(
                    f"Port {port}: {nm[ip_address]['tcp'][port]['name']} {nm[ip_address]['tcp'][port]['product']} {nm[ip_address]['tcp'][port]['version']} ({nm[ip_address]['tcp'][port]['product']})")
        print()
    else:
        print("No open ports found.\n")
    if len(closed_ports) > 0:
        print("Closed ports found:")
        for port in closed_ports:
            print(f"Port {port}: {nm[ip_address]['tcp'][port]['name']}")
        print()


def progressBar(currentValue, TotalValue):
    percentage = int((currentValue/TotalValue)*100)
    progress = int((50*currentValue)/TotalValue)
    loadbar = "Progress: |{:{len}}|{}%".format(
        progress*"█", percentage, len=50)
    print(loadbar, end='\r')


def domainScanner(domainName):
    if not validators.url(domainName):
        print("Invalid Url")
        return
    domainName = domainName.split("//")[-1].split("/")[0].strip()
    print(f"Searching for sub-domains of {domainName}")
    with open('subdomain_names.txt', 'r') as file:
        subDomains = file.read().splitlines()
        foundDomains = []
        for idx, subDomain in enumerate(subDomains):
            progressBar(idx, len(subDomains))
            url = f"https://{subDomain}.{domainName}"
            try:
                requests.get(url)
                foundDomains.append(url)
            except requests.ConnectionError:
                pass
        print("Progress: |██████████████████████████████████████████████████|100%\n")
        print("Domains Found")
        for domain in foundDomains:
            print(f"[+] {domain}")


def dnsRecords(url):
    if not validators.url(url):
        print("Invalid Url")
        return
    dns_records = []
    hostname = url.split("//")[-1].split("/")[0]
    rtypes = ["A", "AAAA", "MX", "NS", "SOA", "TXT"]
    for idx, rtype in enumerate(rtypes):
        progressBar(idx, len(rtypes))
        try:
            for rdata in dns.resolver.Resolver().resolve(hostname, rtype):
                dns_records.append(str(rdata))
        except:
            pass
    print("Progress: |██████████████████████████████████████████████████|100%\n")

    if len(dns_records) > 0:
        print("DNS records found:")
        for record in dns_records:
            print(f"[+] {record}")
    else:
        print("No DNS records found.")


def webServer(url):
    if not validators.url(url):
        print("Invalid Url")
        return
    server_header = requests.get(url).headers.get("Server")
    if server_header:
        print(f"The web server is running {server_header}.")
    else:
        print("No Server header found.")


def websiteInfo(url):
    if not validators.url(url):
        print("Invalid Url")
        return
    domain_info = whois.whois(url)
    print(f"\nDomain name: {domain_info.domain_name}")
    print(f"Registrar: {domain_info.registrar}")
    print(f"Creation date: {domain_info.creation_date}")
    print(f"Expiration date: {domain_info.expiration_date}")
    print(f"Updated date: {domain_info.updated_date}")
    print(f"Registrant name: {domain_info.name}")
    print(f"Registrant organization: {domain_info.org}")
    print(f"Registrant email: {domain_info.emails}")
    print(f"Registrant country: {domain_info.country}")
    print(f"Registrant state: {domain_info.state}")
    print(f"Registrant city: {domain_info.city}")
    print(f"Registrant address: {domain_info.address}\n")


def httpSecurityHeader(url):
    if not validators.url(url):
        print("Invalid Url")
        return
    headers = requests.get(url).headers
    security_headers = {
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "XFO",
        "Strict-Transport-Security": "STH",
        "X-XSS-Protection": "XXP",
        "X-Content-Type-Options": "XCTO",
        "Feature-Policy": "FP",
        "Referrer-Policy": "RP"
        
    }
    print(headers)
    for header, acronym in security_headers.items():
        if header in headers:
            print(f"The site has {acronym} enabled.")
        else:
            print(f"The site has {acronym} disabled.")


while True:
    z = input("1. IP Address\n2. Port Scan\n3. Domain Scanner\n4. DNS Records\n5. Web Server\n6. Website Info\n7. HTTP Security Header\n\nEnter your Choice: ")
    z = int(z)
    url = input("Enter url of the website: ")
    if z == 1:
        ip = ipAddress(url)
        print(f"IP Address of {url} is {ip}")
        print()

    elif z == 2:
        sv = input("Do you want service versions (y/n): ").lower()
        if sv == "y":
            portScan(url, True)
        else:
            portScan(url)
        print()

    elif z == 3:
        domainScanner(url)
        print()

    elif z == 4:
        dnsRecords(url)
        print()

    elif z == 5:
        webServer(url)
        print()

    elif z == 6:
        websiteInfo(url)
        print()

    elif z == 7:
        httpSecurityHeader(url)
        print()

    if input("Do you wish to continue (y/n): ").lower() == "n":
        break
