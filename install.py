import os

req = "apt-get update;apt-get install golang;mkdir /root/Recon;cd /root/Recon;git clone https://github.com/projectdiscovery/subfinder.git;cd subfinder/v2/cmd/subfinder;go build .;mv subfinder /usr/local/bin;cd /root/Recon;git clone https://github.com/projectdiscovery/httpx.git;cd httpx/cmd/httpx;go build .;mv httpx /usr/local/bin;cd /root/Recon;git clone https://github.com/projectdiscovery/nuclei.git;cd nuclei/v2/cmd/nuclei;go build .;mv nuclei /usr/local/bin;cd /root/Recon/nuclei/v2/cmd/functional-test;go build .;mv functional-test /usr/local/bin;cd /root/Recon/nuclei/v2/cmd/integration-test;go build .;mv integration-test /usr/local/bin;cd /root/Recon;git clone https://github.com/projectdiscovery/notify.git;cd notify/cmd/notify;go build .;mv notify /usr/local/bin;cd /root/Recon;git clone https://github.com/tomnomnom/anew.git;cd anew;go mod init anew;go build .;mv anew /usr/local/bin; sudo apt install metagoofil;"
os.system(req)
