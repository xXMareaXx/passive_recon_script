#!/usr/bin/python3
from googlesearch import search
from enum import Enum
import os
import argparse
import shodan
from urllib.parse import urlparse

GOOGLE_DORKS_OPTIONS = {
    1:  ["Footholds",                      "footholds_query.txt"],
    2:  ["File Containing Usernames",      "file_usernames_query.txt"],
    3:  ["Sensitives Directories",         "sensitives_directories_query.txt"],
    4:  ["Web Server Detection",           "webserver_query.txt"],
    5:  ["Vulnerable Files",               "vulnerable_files_query.txt"],
    6:  ["Vulnerable Servers",             "vulnerable_servers_query.txt"],
    7:  ["Error Messages",                 "error_messages_query.txt"],
    8:  ["File Containing Juicy Info",     "files_juicy_info_query.txt"],
    9:  ["File Containing Passwords",      "files_passwords_query.txt"],
    10: ["Sensitive Online Shopping Info", "sensitive_shopping_info.txt"],
    11: ["Network or Vulnerability Data",  "network_vuln_data.query"],
    12: ["Pages Containing Login Portals", "login_portals.query"],
    13: ["Various Online devices",         "online_devices_query.txt"],
    14: ["Advisories and Vulnerabilities", "advisories_vulnerabilities_query.txt"]
}

def install_tool():
    req = "apt-get update;apt-get install golang;mkdir /root/Recon;cd /root/Recon;git clone https://github.com/projectdiscovery/subfinder.git;cd subfinder/v2/cmd/subfinder;go build .;mv subfinder /usr/local/bin;cd /root/Recon;git clone https://github.com/projectdiscovery/httpx.git;cd httpx/cmd/httpx;go build .;mv httpx /usr/local/bin;cd /root/Recon;git clone https://github.com/projectdiscovery/nuclei.git;cd nuclei/v2/cmd/nuclei;go build .;mv nuclei /usr/local/bin;cd /root/Recon/nuclei/v2/cmd/functional-test;go build .;mv functional-test /usr/local/bin;cd /root/Recon/nuclei/v2/cmd/integration-test;go build .;mv integration-test /usr/local/bin;cd /root/Recon;git clone https://github.com/projectdiscovery/notify.git;cd notify/cmd/notify;go build .;mv notify /usr/local/bin;cd /root/Recon;git clone https://github.com/tomnomnom/anew.git;cd anew;go mod init anew;go build .;mv anew /usr/local/bin"
    os.system(req)

def read_file(file_name):
    # Method for reading the hosts file
    file1 = open(file_name, 'r')
    return file1.readlines()

def run_subfinder(url):
    # Method for running gsubfinder (-s option)
    os.system("subfinder -d " + urlparse(url).netloc) #Using urlparse for getting domain from URL

def run_google_dorking(hosts_file, query_file):
    # Method for running google dorks (-g option)
    results = []
    print(hosts_file)
    print(query_file)
    google_queries = read_file("google_queries/" + query_file)
    hosts          = read_file(hosts_file)
    #print(hosts)
    for query in google_queries:
        for host in hosts:
            print("--------------- Query: " + query + " ---------------")
            print(host)
            print(urlparse(host).netloc)
            for j in search(query + " inurl:" + urlparse(host).netloc, num = 15, lang = "en", pause = 10):
                results.append(j)
    return results

def run_nuclei(url):
    # Method for running nuclei with all templates (-n option)
    print("Running nuclei")

def run_nslookup(url):
    # Method for running nslookup (-ns option)
    print("Google Dorking")
  
def run_whatweb(url):
    # Method for running whatweb (-w option)
    print("Running subfinder")

def run_shodan(url):
    # Method for running shodan (-s option)
    print("Plantear si hacer shodan")

def run_all_tools(domain, url):
    # Method for running all tools (-a option)
    print("Running nuclei")

def parse_arguments():
    parser = argparse.ArgumentParser("passive_recon_script", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-i",   help = "Install tool",                                                   action = "store_true", required = False)
    parser.add_argument("-g",   help = "Run google dorks. \n\nOptions:\n\n1: Footholds\n2: File containing Usernames\n3: Sensitives Directories\n4: Web Server Detection\n5: Vulnerable Files\n6: Vulnerable Servers\n7: Error Messages\n8: File Containing Juicy Info\n9: File Containing Passwords\n10: Sensitive Online Shopping Info\n11: Network or Vulnerability Data\n12: Pages Containing Login Portals\n13: Various Online Devices\n14: Advisories and Vulnerabilities\n\n", metavar = "option", required = False)
    parser.add_argument("-sub", help = "Look for Subdomains",                                            action = "store_true", required = False)
    #parser.add_argument("-s",   help = "Run Shodan",                                                     action = "store_true", required = False)
    parser.add_argument("-ns",  help = "Run nslookup",                                                   action = "store_true", required = False)
    parser.add_argument("-n",   help = "Run nuclei",                                                     action = "store_true", required = False)
    parser.add_argument("-w",   help = "Run whatweb",                                                    action = "store_true", required = False)
    parser.add_argument("-a",   help = "Run all tools",                                                  action = "store_true", required = False)
    parser.add_argument("host_file") #Positional argument
    return parser

def selected_option():
    print("Get selected option")

def main():
    parser = parse_arguments()
    # Parsing args
    args, unknownargs = parser.parse_known_args()
    print(args)
    print(unknownargs)
    print(args.g)
    run_google_dorking("hosts.txt", GOOGLE_DORKS_OPTIONS[int(args.g)][1])


if __name__ == '__main__':
    main()
