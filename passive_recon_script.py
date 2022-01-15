#!/usr/bin/python3
from googlesearch import search
from enum import Enum
import os
import argparse
import shodan
from urllib.parse import urlparse
  
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
    
def run_google_dorking(url):
    # Method for running google dorks (-g option)
    results = []
    google_queries = read_file("google_query_test.txt")
    for query in google_queries:
        print("--------------- Query: " + query + " ---------------")
        for j in search(query + " inurl:" + urlparse(url).netloc, num = 15, lang = "en", pause = 2):
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
    parser = argparse.ArgumentParser("passive_recon_script")
    parser.add_argument("-i",   help = "Install tool",                                                   action = "store_true", required = False)
    parser.add_argument("-g",   help = "Run google dorks with the queries in file 'google_queries.txt'", action = "store_true", required = False)
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

    for host in read_file(args.host_file):
        run_google_dorking(host)


if __name__ == '__main__':
    main()