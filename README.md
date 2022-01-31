# Passive Recon Script

Passive Recon Script is a Python script for doing the passive recon tasks in an automated way.

The main goal of this script is make all the **passive recon phase in only one step**.

This script centralize some passive recon tools:

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [GHDB](https://www.exploit-db.com/google-hacking-database)
- [Metagoofil](https://www.kali.org/tools/metagoofil/)
- [Nslookup](https://docs.microsoft.com/es-es/windows-server/administration/windows-commands/nslookup)
- [Whatweb](https://github.com/urbanadventurer/WhatWeb)

## Installation

Use the [install.py](https://github.com/xXMareaXx/passive_recon_script/blob/main/install.py) file for installing the necessary tools for passive_scan_script:

```bash
python3 install.py
```

## Usage
Inside this directory there is a file called **hosts.txt** that contains the list of the hosts you want to scan for. Modify it.

There is also a [config.yml](https://github.com/xXMareaXx/passive_recon_script/blob/main/config.yml) file that contains some configuration. Modify it with the api keys needed (for example, Shodan api key)

For showing the help for this tool run -h option:

```bash
python3 passive_recon_script.py -h
```

- For search subdomains with [Subfinder](https://github.com/projectdiscovery/subfinder) run **-sub** option.
- For search vulnerabilities with [Nuclei](https://github.com/projectdiscovery/nuclei) run **-n** option.
- For search DNS information with [Nslookup](https://docs.microsoft.com/es-es/windows-server/administration/windows-commands/nslookup) run **-ns** option.
- For [Google Dorks](https://www.exploit-db.com/google-hacking-database) run **-g <google_dorks_option>** option.
- For general information of the web with [Whatweb](https://github.com/urbanadventurer/WhatWeb) run **-w** option.
- For getting files related with the host using [Metagoofil](https://www.kali.org/tools/metagoofil/) run **-m <file_type>** option.
- For look for the IP with [Shodan](https://www.shodan.io/) run **-s** option.

Almost all tools are launched by default, but there are two of theme that should be ran with arguments:

#### GHDB
There are some options available for google dorks:
- 0: Custom Queries
- 1: Footholds
- 2: File Containing Usernames
- 3: Sensitives Directories
- 4: Web Server Detection
- 5: Vulnerable Files
- 6: Vulnerable Servers
- 7: Error Messages
- 8: File Containing Juicy Info
- 9: File Containing Passwords
- 10: Sensitive Online Shopping Info
- 11: Network or Vulnerability Data
- 12: Pages Containing Login Portals
- 13: Various Online devices
- 14: Advisories and Vulnerabilities

This way, you can launch the tool with one of these options, for example:

```bash
python3 passive_recon_script.py -g 0
```
The files with the queries extracted from [GHDB](https://www.exploit-db.com/google-hacking-database) are in [google_queries](https://github.com/xXMareaXx/passive_recon_script/tree/main/google_queries) directory. The file [custom_queries.txt](https://github.com/xXMareaXx/passive_recon_script/blob/main/google_queries/custom_queries.txt) should contain your custom google queries.

#### Metagoofil
Run it with the file type you want to search as option, for example:

```bash
python3 passive_recon_script.py -m pdf
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
