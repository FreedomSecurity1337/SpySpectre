# recode semau lu asal jangan di jual kontol malu maluin agus
# credits : IZS Group - Russian Cyber Ford

import os
import sys
import pyfiglet
from colorama import Fore, Style, init
import socket
import whois
import ssl
import requests
from tabulate import tabulate
import pytz
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

init(autoreset=True)
os.system("clear")
def print_banner():
    banner = pyfiglet.figlet_format("SpySpectre", font="slant", width=1000)
    print(f"{Fore.RED}{banner}{Fore.RESET}")
    print(f"{Fore.RED}-{'~' * 48}-")
    print(f"{Fore.CYAN}~{Fore.GREEN} SpySpectre 2025 {Fore.WHITE}info at your fingertips")
    print(f"{Fore.RED}-{'~' * 48}-")
    print(f"{Fore.CYAN}~{Fore.GREEN} Version      => {Fore.WHITE}1.0 (alpha test)")
    print(f"{Fore.CYAN}~{Fore.GREEN} Packages     => {Fore.WHITE}Information Gathering")
    print(f"{Fore.CYAN}~{Fore.GREEN} Developed By => {Fore.WHITE}./Freedom Security")
    print(f"{Fore.CYAN}-{'~' * 48}-\n")

def main_menu():
    print(f"{Fore.CYAN}~{Fore.GREEN} Choose an option:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}1.{Fore.WHITE} WHOIS Information    | {Fore.CYAN}11.{Fore.WHITE} HTTP Header check")
    print(f"{Fore.CYAN}2.{Fore.WHITE} Server Information")
    print(f"{Fore.CYAN}3.{Fore.WHITE} SSL/TLS Information")
    print(f"{Fore.CYAN}4.{Fore.WHITE} Domain to IP")
    print(f"{Fore.CYAN}5.{Fore.WHITE} IP Tracker")
    print(f"{Fore.CYAN}6.{Fore.WHITE} Port Scanner")
    print(f"{Fore.CYAN}7.{Fore.WHITE} HTTP Request Checker")
    print(f"{Fore.CYAN}8.{Fore.WHITE} Reverse IP")
    print(f"{Fore.CYAN}9.{Fore.WHITE} Subdomain Enumerate")
    print(f"{Fore.CYAN}10.{Fore.WHITE} SSL Certificate")

def http_header_check(domain):
    try:
        response = requests.get(f'http://{domain}', timeout=5)
        headers = {
            "Domain": domain,
            "HTTP Status": f"{response.status_code} {response.reason}",
            "Content-Type": response.headers.get('Content-Type', 'N/A'),
            "Server": response.headers.get('Server', 'N/A'),
            "X-Powered-By": response.headers.get('X-Powered-By', 'N/A'),
            "Date": response.headers.get('Date', 'N/A')
        }
        return headers
    except Exception as e:
        return {"Error": f"HTTP Header Error: {e}"}

def ssl_certif(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        cert_obj = x509.load_pem_x509_certificate(cert.encode('utf-8'), default_backend())
        cert_info = {
            "Domain": domain,
            "Issuer": cert_obj.issuer,
            "Subject": cert_obj.subject,
            "Not Before": cert_obj.not_valid_before,
            "Not After": cert_obj.not_valid_after
        }
        return cert_info
    except Exception as e:
        return {"Error": f"SSL/TLS Error: {e}"}

def subdo_find(domain):
    try:
        api_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            subdomains = []
            data = response.json()
            for entry in data:
                subdomain = entry.get("name_value", "")
                if subdomain:
                    try:
                        ip = socket.gethostbyname(subdomain)
                        subdomains.append({"Subdomain": subdomain, "IP": ip})
                    except socket.gaierror:
                        subdomains.append({"Subdomain": subdomain, "IP": "N/A"})
            if subdomains:
                return {"Domain": domain, "Subdomains": subdomains}
            else:
                return {"Domain": domain, "Subdomains": "No subdomains found"}
        else:
            return {"Error": f"API Response Error: {response.status_code}"}
    except Exception as e:
        return {"Error": f"Subdomain Enumeration Error: {e}"}

def reverse_ip_lookup(ip):
    try:
#        api_url = f"https://sonar.omnisint.io/reverse/{ip}" ganti pake yang bisa
        api_url = f"http://ip-api.com/json/{ip}"
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            domains = response.json()
            if domains:
                return {"IP Address": ip, "Domains": ", ".join(domains[:10]) + ("..." if len(domains) > 10 else "")}
            else:
                return {"IP Address": ip, "Domains": "No domains found"}
        else:
            return {"Error": f"API Response Error: {response.status_code}"}
    except Exception as e:
        return {"Error": f"Reverse IP Error: {e}"}

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "Domain": domain,
            "Registrar": w.registrar or "N/A",
            "Creation Date": w.creation_date or "N/A",
            "Expiration Date": w.expiration_date or "N/A",
            "Name Servers": ", ".join(w.name_servers) if w.name_servers else "N/A",
        }
    except Exception as e:
        return {"Error": f"WHOIS Error: {e}"}

def get_server_info(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        return {
            "Server": response.headers.get("Server", "Unknown"),
            "X-Powered-By": response.headers.get("X-Powered-By", "Unknown"),
            "Content-Type": response.headers.get("Content-Type", "Unknown"),
        }
    except Exception as e:
        return {"Error": f"Server Info Error: {e}"}

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "Issuer": cert.get("issuer")[0][0][1],
                    "Valid From": cert.get("notBefore"),
                    "Valid To": cert.get("notAfter"),
                    "Wildcard": "Yes" if "*." in cert.get("subjectAltName", [("", "")])[0][1] else "No",
                }
    except Exception as e:
        return {"Error": f"SSL Info Error: {e}"}

def domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return {"Domain": domain, "IPv4": ip_address}
    except Exception as e:
        return {"Error": f"Domain to IP Error: {e}"}

def ip_tracker(ip):
    try:
        ip_info = {}

        try:
            ipv6 = socket.getaddrinfo(ip, None, socket.AF_INET6)
            ip_info["IPv6"] = ipv6[0][4][0]
        except socket.gaierror:
            ip_info["IPv6"] = "N/A"

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            ip_info["Hostname"] = hostname
        except socket.herror:
            ip_info["Hostname"] = "N/A"

        api_url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            ip_info["IP Address"] = ip
            ip_info["IP Range"] = data.get("range", "N/A")
            ip_info["ISP"] = data.get("org", "N/A").split(" ")[0]
            ip_info["Organization"] = " ".join(data.get("org", "N/A").split(" ")[1:])
            ip_info["Country"] = f"{data.get('country', 'N/A')} ({data.get('country', 'N/A')})"
            ip_info["Region"] = data.get("region", "N/A")
            ip_info["City"] = data.get("city", "N/A")
            ip_info["Timezone"] = data.get("timezone", "N/A")
            ip_info["Postal Code"] = data.get("postal", "N/A")

            if data.get("timezone"):
                tz = pytz.timezone(data["timezone"])
                local_time = datetime.now(tz).strftime("%H:%M:%S (%Z) / %Y.%m.%d")
                ip_info["Local Time"] = local_time
            else:
                ip_info["Local Time"] = "N/A"

        else:
            ip_info.update({
                "IP Address": ip,
                "IP Range": "N/A",
                "ISP": "N/A",
                "Organization": "N/A",
                "Country": "N/A",
                "Region": "N/A",
                "City": "N/A",
                "Timezone": "N/A",
                "Postal Code": "N/A",
                "Local Time": "N/A",
            })

        return ip_info

    except Exception as e:
        return {"Error": f"IP Tracker Error: {e}"}

def port_scanner(domain, ports):
    result = []
    try:
        ip = socket.gethostbyname(domain)
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                sock.connect((ip, port))
                result.append({"Port": port, "Status": "Open"})
            except:
                result.append({"Port": port, "Status": "Closed"})
            finally:
                sock.close()
    except Exception as e:
        result = [{"Port": "Error", "Status": str(e)}]
    return result

def http_request(domain, method):
    try:
        url = f"http://{domain}"
        response = requests.request(method, url, timeout=5)
        return {
            "Method": method,
            "Status Code": response.status_code,
            "Reason": response.reason,
            "Elapsed Time": f"{response.elapsed.total_seconds()}s",
        }
    except Exception as e:
        return {"Error": f"HTTP Request Error: {e}"}


def display_table(title, data, headers):
    print(f"\n{Fore.GREEN}{title}{Style.RESET_ALL}")
    if isinstance(data, list) and isinstance(data[0], dict):
        data_table = [[f"{Fore.GREEN}{key}{Style.RESET_ALL}", value] for d in data for key, value in d.items()]
    else:
        data_table = [[f"{Fore.GREEN}{header}{Style.RESET_ALL}", value] for header, value in data.items()]
    print(tabulate(data_table, headers=headers, tablefmt="fancy_grid"))

def main():

    while True:
        print_banner()
        main_menu()
        choice = input(f"{Fore.GREEN}--({Fore.WHITE}choice{Fore.GREEN})--~> {Fore.WHITE}").strip()

        if choice == "1":
            domain = input("Enter domain: ").strip()
            whois_info = get_whois_info(domain)
            display_table("WHOIS Information", whois_info, ["Field", "Details"])
        elif choice == "2":
            domain = input("Enter domain: ").strip()
            server_info = get_server_info(domain)
            display_table("Server Information", server_info, ["Field", "Details"])
        elif choice == "3":
            domain = input("Enter domain: ").strip()
            ssl_info = get_ssl_info(domain)
            display_table("SSL/TLS Information", ssl_info, ["Field", "Details"])
        elif choice == "4":
            domain = input("Enter domain: ").strip()
            ip_info = domain_to_ip(domain)
            display_table("Domain to IP", ip_info, ["Field", "Details"])
        elif choice == "5":
            ip = input("Enter IP: ").strip()
            ip_info = ip_tracker(ip)
            display_table("IP Tracker", ip_info, ["Field", "Details"])
        elif choice == "6":
            domain = input("Enter domain: ").strip()
            ports = input("Enter comma-separated ports (e.g., 80,443): ").split(",")
            ports = [int(port.strip()) for port in ports]
            result = port_scanner(domain, ports)
            display_table("Port Scanner", result, ["Port", "Status"])
        elif choice == "7":
            domain = input("Enter domain: ").strip()
            method = input("Enter HTTP method (GET/POST/PUT/etc.): ").strip()
            http_info = http_request(domain, method)
            display_table("HTTP Request Checker", http_info, ["Field", "Details"])
        elif choice == "8":
            ip = input("Enter IP: ").strip()
            reverse_info = reverse_ip_lookup(ip)
            display_table("Reverse IP Lookup", reverse_info, ["Field", "Details"])
        elif choice == "9":
            domain = input("Enter domain: ").strip()
            subdomains_info = subdo_find(domain)
            display_table("Subdomain Enumeration", subdomains_info["Subdomains"], ["Subdomain", "IP"])
        elif choice == "10":
             domain = input(f"{Fore.WHITE}Enter domain: {Fore.WHITE}")
             ssl_info = ssl_certif(domain)
             display_table("SSL/TLS Information", ssl_info, ["Field", "Details"])
        elif choice == "11":
             domain = input(f"{Fore.GREEN}[?] Masukkan domain: {Fore.WHITE}")
             http_headers = http_header_check(domain)
             display_table("HTTP Header Check", http_headers, ["Field", "Details"])
        elif choice == "banner":
             print_banner()
        elif choice == "exit":
            print(f"{Fore.RED}Exiting...")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid menu Executing command for input: {choice}")
            os.system(choice)

if __name__ == "__main__":
    main()
