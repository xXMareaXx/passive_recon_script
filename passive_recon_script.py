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
        return urlparse(url).netloc
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
    try:
        os.system("subfinder -d " + get_domain_from_url(url)) #Using urlparse for getting domain from URL
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
            for j in search(query + " inurl:" + get_domain_from_url(url), num = 5, lang = "en", pause = 60):
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
    # Method for running shodan (-s option)
    try:
        print("Plantear si hacer shodan")
    except Exception as e:
        print(colored(e, "red"))

def run_theharvester(url):
    # Method for running TheHarvester (-th option)
    try:
        print("Running The Harvester...")
    except Exception as e:
        print(colored(e, "red"))


def run_metagoofil(file_type, url):
    print(colored("--------------------- METAGOOFIL ---------------------", "green"))
    # Method for running Metagoofil (-m)
    try:
        configuration = read_config_file()
        os.system("metagoofil -d " + get_domain_from_url(url) + " -t " + file_type + " -l " + str(configuration["metagoofil"]["total_results"]) + " -n " + str(configuration["metagoofil"]["total_downloads"]) + " -o " + str(configuration["metagoofil"]["output_directory"] + " -f "))
    except Exception as e:
        print(colored(e, "red"))

def parse_arguments():
    parser = argparse.ArgumentParser("passive_recon_script", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-sub", help = "Look for Subdomains", action  = "store_true", required = False)
    #parser.add_argument("-s",   help = "Run Shodan",         action  = "store_true", required = False)
    parser.add_argument("-ns",  help = "Run nslookup",        action  = "store_true", required = False)
    parser.add_argument("-n",   help = "Run nuclei",          action  = "store_true", required = False)
    parser.add_argument("-m",   help = "Run Metagoofil",      metavar = "file_type" , required = False)
    parser.add_argument("-th",  help = "Run The Harvester",   action  = "store_true", required = False)
    parser.add_argument("-w",   help = "Run whatweb",         action  = "store_true", required = False)
    parser.add_argument("-g",   help = "Run google dorks. \n\nOptions:\n\n0: Your Custom Queries (modify google_queries/custom_queries.txt including your google queries) file\n1: Footholds\n2: File containing Usernames\n3: Sensitives Directories\n4: Web Server Detection\n5: Vulnerable Files\n6: Vulnerable Servers\n7: Error Messages\n8: File Containing Juicy Info\n9: File Containing Passwords\n10: Sensitive Online Shopping Info\n11: Network or Vulnerability Data\n12: Pages Containing Login Portals\n13: Various Online Devices\n14: Advisories and Vulnerabilities\n\n", metavar = "option", required = False)
    parser.add_argument("-a",   help = "Run all tools",       metavar = "google_dorks_option", required = False)
    parser.add_argument("host_file") #Positional argument
    return parser

def selected_option(args):
    try:
        for host in read_file("hosts.txt"):
            if args.a:
                run_subfinder(host)
                run_nslookup(host)
                run_nuclei(host)
                run_whatweb(host)
                run_metagoofil(args.m, host)
                run_theharvester(host)
                run_google_dorking(int(args.a), host)
            else:
                if args.sub:
                    run_subfinder(host)
                if args.ns:
                    run_nslookup(host)
                if args.n:
                    run_nuclei(host)
                if args.w:
                    run_whatweb(host)
                if args.g:
                    run_google_dorking(int(args.g), host)
                if args.th:
                    run_theharvester(host)
                if args.m:
                    run_metagoofil(args.m, host)
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
