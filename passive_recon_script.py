#!/usr/bin/python3
from googlesearch import search
from enum import Enum
import os
import argparse
import shodan
from urllib.parse import urlparse
import time
from termcolor import colored
import yaml
import socket
import json
import sys

GOOGLE_DORKS_OPTIONS_FILES = {
    0:  "custom_queries.txt",
    1:  "footholds_query.txt",
    2:  "file_usernames_query.txt",
    3:  "sensitives_directories_query.txt",
    4:  "webserver_query.txt",
    5:  "vulnerable_files_query.txt",
    6:  "vulnerable_servers_query.txt",
    7:  "error_messages_query.txt",
    8:  "files_juicy_info_query.txt",
    9:  "files_passwords_query.txt",
    10: "sensitive_shopping_info.txt",
    11: "network_vuln_data.query",
    12: "login_portals.query",
    13: "online_devices_query.txt",
    14: "advisories_vulnerabilities_query.txt"
}

CONFIG_FILE = "config.yml"

def read_config_file():
    try:
        file = open("config.yml", "r")
        return yaml.safe_load(file)
    except Exception as e:
        print(colored(e, "red"))

def get_domain_from_url(url):
    try:
        return '.'.join(urlparse(url).netloc.split(".")[-2:])
    except Exception as e:
        print(colored(e, "red"))

def read_file(file_name):
    # Method for reading a file line by line
    try:
        file1 = open(file_name, 'r')
        return file1.readlines()
    except Exception as e:
        print(colored(e, "red"))

def run_subfinder(url):
    # Method for running gsubfinder (-sub option)
    print(" Subfinder ")
    try:
        os.system("subfinder -d " + get_domain_from_url(url) + " -silent") #Getting domain from URL and options -silent for only result in output
    except Exception as e:
        print(colored(e, "red"))

def run_google_dorking(option, url):
    # Method for running google dorks (-g option)
    results        = []
    query_file     = GOOGLE_DORKS_OPTIONS_FILES[option]
    try:
        google_queries = read_file("google_queries/" + query_file)
        for query in google_queries:
            print("---- " + query + " ----")
            for j in search(query + " inurl:" + get_domain_from_url(url), num = 5, lang = "en", pause = 80):
                results.append({"query": query, "result": j})
    except Exception as e:
        print(colored(e, "red"))
    return results

def run_nuclei(url):
    # Method for running nuclei with all templates (-n option)
    try:
        os.system("nuclei -u " + url)
    except Exception as e:
        print(colored(e, "red"))

def run_nslookup(url):
    # Method for running nslookup (-ns option)
    print(colored("--------------------- NSLOOKUP ---------------------", "green"))
    try:
        os.system("nslookup " + url)
    except Exception as e:
        print(colored(e, "red"))

def run_whatweb(url):
    # Method for running whatweb (-w option)
    print(colored("--------------------- WHATWEB ---------------------", "green"))
    try:
        os.system("whatweb " + url)
    except Exception as e:
        print(colored(e, "red"))

def run_shodan(url):
    return_shodan = ""
    # Method for running shodan (-s option)
    #try:
    api     = shodan.Shodan(read_config_file()["shodan"]["api_key"])
    host_ip = socket.gethostbyname(urlparse(url).netloc) # Getting IP from URL
    host    = api.host(host_ip)
    #json.dumps(host, sort_keys=True, indent=4)
    print(colored ("---- Hostnames ----", "blue"))
    print(host["hostnames"])
    print(colored ("---- Domains ----", "blue"))
    print(host["domains"])
    # Print all banners
    for item in host['data']:
        print(colored("Port: ", "green")   + str(item['port']))
        print(colored("Banner:\n", "green") + str(item['data']))

    # Print vuln information
    if "vulns" in host:
        for vuln in host['vulns']:
            CVE = vuln.replace('!','')
            print(colored("Vulns: " + vuln, "red"))    

def run_metagoofil(file_type, url):
    print(colored("--------------------- METAGOOFIL ---------------------", "green"))
    # Method for running Metagoofil (-m)
    try:
        configuration = read_config_file()
        os.system("cd metagoofil; python3 metagoofil.py -d " + urlparse(url).netloc + " -t " + file_type + " -l " + str(configuration["metagoofil"]["total_results"]) + " -n " + str(configuration["metagoofil"]["total_downloads"]))
        #os.system("metagoofil -d " + urlparse(url).netloc + " -t " + file_type + " -l " + str(configuration["metagoofil"]["total_results"]) + " -n " + str(configuration["metagoofil"]["total_downloads"]) + " -o " + str(configuration["metagoofil"]["output_directory"] + " -f "))
    except Exception as e:
        print(colored(e, "red"))

def parse_arguments():
    parser = argparse.ArgumentParser("passive_recon_script",  formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument("-sub", help = "Look for Subdomains with Subfinder", action  = "store_true", required = False)
    parser.add_argument("-s",   help = "Run Shodan",                         action  = "store_true", required = False)
    parser.add_argument("-ns",  help = "Run Nslookup",                       action  = "store_true", required = False)
    parser.add_argument("-n",   help = "Run Nuclei",                         action  = "store_true", required = False)
    parser.add_argument("-m",   help = "Run Metagoofil",                     metavar = "file_type" , required = False)
    parser.add_argument("-w",   help = "Run Whatweb",                        action  = "store_true", required = False)
    parser.add_argument("-g",   help = "Run google dorks. \n\nOptions:\n\n0: Your Custom Queries (modify google_queries/custom_queries.txt including your google queries) file\n1: Footholds\n2: File containing Usernames\n3: Sensitives Directories\n4: Web Server Detection\n5: Vulnerable Files\n6: Vulnerable Servers\n7: Error Messages\n8: File Containing Juicy Info\n9: File Containing Passwords\n10: Sensitive Online Shopping Info\n11: Network or Vulnerability Data\n12: Pages Containing Login Portals\n13: Various Online Devices\n14: Advisories and Vulnerabilities\n\n", metavar = "option", required = False)
    #parser.add_argument("-a",   help = "Run all tools",       metavar = "google_dorks_option", required = False)
    parser.add_argument("hosts_file") #Positional argument
    return parser

def selected_option(args):
    return_subfinder    = ""
    return_nslookup     = ""
    return_nuclei       = ""
    return_whatweb      = ""
    return_metagoofil   = ""
    return_google_dorks = ""
    return_shodan       = ""
    for host in read_file("hosts.txt"):
       # if args.a:
       #     return_subfinder    = run_subfinder(host)
       #     return_nslookup     = run_nslookup(host)
       #     return_nuclei       = run_nuclei(host)
       #     return_whatweb      = run_whatweb(host)
       #     return_metagoofil   = run_metagoofil(args.m, host)
       #     return_google_dorks = run_google_dorking(int(args.a), host)
       #     return_shodan       = run_shodan(host)
       # else:
        if args.sub:
            return_subfinder    = run_subfinder(host)
        if args.ns:
            return_nslookup     = run_nslookup(host)
        if args.n:
            return_nuclei       = run_nuclei(host)
        if args.w:
            return_whatweb      = run_whatweb(host)
        if args.g:
            return_google_dorks = run_google_dorking(int(args.g), host)
        if args.m:
            return_metagoofil   = run_metagoofil(args.m, host)
        if args.s:
            return_shodan       = run_shodan(host)

    print_html_report(return_subfinder, return_nslookup, return_nuclei, return_metagoofil, return_whatweb, return_google_dorks, return_shodan)

def print_html_report(subfinder_result, nslookup_result, nuclei_result, metagoofil_result, whatweb_result, google_dorks_result, shodan_result):
    print(colored("--------------------- Print HTML ---------------------", "green"))
    try:
        f = open("passive_recon_script_report.html", "a")
        #f.write(shodan_result)
        print("HTML Report")
    except Exception as e:
        print(colored(e, "red"))

def main():
    parser = parse_arguments()
    # Parsing args
    args, unknownargs = parser.parse_known_args()
    print(args)
    selected_option(args)


if __name__ == '__main__':
    main()
