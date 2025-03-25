import os
import requests
import whois
import json
import socket
import shodan
import subprocess
import re
import subprocess
import logging
import time
from bs4 import BeautifulSoup
from dotenv import load_dotenv

#Load environment variables from .env file
load_dotenv()

#API Keys (Loaded from environment variables)
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
HIBP_API_KEY = os.getenv('HIBP_API_ENV')

#Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Input santization function
def sanitize_input(input_string):
    """
    Sanitize user input to prevent injection attacks.
    
    :param input_string: User-provided input
    :return: Sanitized input string
    """
    return re.sub(r'[^a-zA-Z0-9\.\-_]', '', input_string)

# WHOIS Lookup
def whois_lookup(domain):
    """
    Perform a WHOIS lookup for the given domain.
    :param domain: Domain name(e.g., example.com)
    :return: WHOIS information or error message
    """
    try:
        result = whois.whois(domain)
        return result
    except Exception as e:
        logging.error(f"WHOIS lookup failed: {e}")
        return f"WHOIS lookup failed: {e}"

# Shodan Scan
def shodan_scan(ip):
    """
    Perfomr a Shodan scan on the given P address
    :param ip: IP address to scan
    :return: Shodan results or error message
    """
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.host(ip)
        return json.dumps(results, indent=4)
    except shodan.APIError as e:
        logging.error(f"Shodan error: {e}")
        return f"Shodan error: {e}"

#DNS Lookup
def dns_lookup(domain):
    """
    Perform a DNS lookup for the given domain.
    :param domain: Domain name(e.g., example.com)
    :return:IP address or error message
    """
    try:
        return socket.gethostbyname(domain)
    except socket.error as e:
        logging.error(f"DNS lookup failed: {e}")
        return f"DNS lookup failed: {e}"

# Metadata Extraction
def extract_metadata(file_path):
    """
    Extract metadata fro a file using exiftool
    :param file_path: Path to the file
    :retun: Metadata or error message
    """
    try:
        output = subprocess.check_output(['exiftool', file_path]).decode()
        return output
    except Exception as e:
        logging.error(f"Metadata extraction failed {e}")
        return f"Metadata extraction failed: {e}"
# Social Media Scraping
def social_media_scrape(username):
    def social_media_scrape(username):
        """
        Scrape social media platforms for the given username.
        :param username: Username to search for
        :return: Dictionary of results
        """
        urls = [
            f"https://x.com/{username}/",
            f"https://www.instagram.com/{username}/",
            f"https://github.com/{username}/",
            f"https://www.linkedin.com/in/{username}/",
            f"https://www.reddit.com/user/{username}/"
        ]
        results = {}
        for url in urls:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    results[url] = "Profile Found"
                else:
                    results[url] = "Not Found"
                time.sleep(1) # Rate Limiting
            except Exception as e:
                results[url] = f"Error: {e}"
            return results
# Dark Web Monitoring
def dark_web_monitor(query):
    """
    Monitor the dark web for the given query
    :param query: Search term
    :return: List of results
    """
    url = f"http://onionsearchengine.com/search?q={query}"
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        results = [link['href'] for link in soup.find_all('a',href = True) if 'http' in link['href']]
        return results
    except Exception as e:
        logging.error(f"Dark web monitoring failed: {e}")
        return f"Dark web monitoring failed: {e}"

#HIBP (Have I Been Pwned) Check
def hibp_check(email):
    """
    Check if an email has been involved in a data breach using HIBP
    :param email: Email address to check
    :return: Breach information or erro message
    """
    headers = {'hibp-api-key': HIBP_API_KEY}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return "No breaches found"
    except Exception as e:
        logging.error(f"HIBP check failed: {e}")
        return f"HIBP check failed: {e}"

# Main Menu
def main_menu():
    """
    Dispay the main menu and handle user input
    """
    print("\n=== OSINT Recon Toolkit ===")
    print("1. WHOIS Lookup")
    print("2. Shodan Scan")
    print("3. DNS Lookup")
    print("4. Social Media OSINT")
    print("5. Dark Web Monitoring")
    print("6. HIBP Check")
    print("7. Exit")
    choice = input("Select an option: ")
    return choice

# Main Function
if __name__ == "__main__":
    print("Disclaimer: Thos tool i for educational and authorized purposes only. Misuse of this tool is prohibited.")

    while True:
        choice = main_menu()
        if choice == "1":
            target = sanitize_input(input("Enter target domain: "))
            print("\n[WHOIS Lookup]")
            print(whois_lookup(target))
        elif choice == "2":
            target = sanitize_input(input("Enter target IP: "))
            print("\n[Shodan Scan]")
            print(shodan_scan(target))
        elif choice == "3":
            target = sanitize_input("Enter target domain: ")
            print("\n[DNS Lookup]")
            print(dns_lookup(target))
        elif choice == "4":
            username = sanitize_input(input("Enter target: username: "))
            print("\n[Social Media OSINT]")
            print(json.dumps(social_media_scrape(username), indent=4))
        elif choice == "5":
            query = sanitize_input(input("Enter search query: "))
            print("\n[Dark web Monitoring]")
            print(dark_web_monitor(query))
        elif choice == "6":
            email = sanitize_input(input("Enter email address: "))
            print("\n[HIBP Check]")
            print(hibp_check(email))
        elif choice == "7":
            print("Exiting..")
            break
        else:
            print("Invalid choice. Please try again.")
