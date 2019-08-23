# Sudomy
[![License](https://img.shields.io/badge/license-MIT-red.svg)](https://opensource.org/licenses/MIT)  [![Version](https://img.shields.io/badge/Release-1.1.0-blue.svg?maxAge=259200)]()   [![Build](https://img.shields.io/badge/Supported_OS-Linux-yellow.svg)]() [![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/screetsec/sudomy/issues)
### Subdomain Enumeration & Analysis
![ff](https://user-images.githubusercontent.com/17976841/63212795-b8d57300-c133-11e9-882a-f604d67819cc.png)

***Sudomy*** is a subdomain enumeration tool, created using a bash script, to analyze domains and collect subdomains in fast and comprehensive way.

## Features !
##### For recent time, ***Sudomy*** has these 9 features:
-  Easy, light, fast and powerful. Bash script is available by default in almost all Linux distributions. By using bash script multiprocessing feature, all processors will be utilized optimally. 
-  Subdomain enumeration process can be achieved by using **active** method or **passive** method
    - **Active Method**
        - *Sudomy* utilize Gobuster tools because of its highspeed performance in carrying out DNS Subdomain Bruteforce attack (wildcard support). The wordlist that is used comes from combined SecList (Discover/DNS) lists which contains around 3 million entries

    - **Passive Method**
        - By selecting the third-party sites, the enumeration process can be optimized. More results will be obtained with less time required. *Sudomy* can collect data from these  well-curated 16 third-party sites:
    
                https://dnsdumpster.com
                https://web.archive.org
                https://shodan.io
                https://virustotal.com
                https://crt.sh
                https://www.binaryedge.io
                https://securitytrails.com
                https://sslmate.com/certspotter
                https://censys.io
                https://threatminer.org
                http://dns.bufferover.run
                https://hackertarget.com
                https://www.entrust.com/ct-search/
                https://www.threatcrowd.org
                https://riddler.io
                https://findsubdomains.com
- Test the list of collected subdomains and probe for working http or https servers. This feature uses a third-party tool, [httprobe](https://github.com/tomnomnom/httprobe "httprobe").
- Subdomain availability test based on Ping Sweep and/or by getting HTTP status code.
- The ability to detect virtualhost (several subdomains which resolve to single IP Address). Sudomy will resolve the collected subdomains to IP addresses, then classify them if several subdomains resolve to single IP address. This feature will be very useful for the next penetration testing/bug bounty process. For instance, in port scanning, single IP address won’t be scanned repeatedly 
- Performed port scanning from collected subdomains/virtualhosts IP Addresses 
- Testing Subdomain TakeOver attack
- Taking Screenshotsof subdomains
- Report output in HTML or CSV format

## How Sudomy Works
*Sudomy* is using cURL library in order to get the HTTP Response Body from third-party sites to then execute the regular expression to get subdomains. This process fully leverages multi processors, more subdomains will be collected with less time consumption.  
## Comparison
The following are the results of passive enumeration DNS testing of *Sublist3r, Subfinder*, and *Sudomy*. The domain that is used in this comparison is ***bugcrowd.com***. 

## Installation

*Sudomy* requires [Node.js](https://nodejs.org/) v4+ to run.

Install the dependencies and devDependencies and start the server.

```sh
$ cd dillinger
$ npm install -d
$ node app
```

For production environments...

```sh
$ npm install --production
$ NODE_ENV=production node app
```


### Third-party Tools
*Sudomy* is currently extended with the following tools. Instructions on how to use them in your own application are linked below.
|  Tools | URL   | License   |
| ------------ | ------------ | ------------ |
|  Httprobe  | https://github.com/tomnomnom/httprobe  |  |
|  Gobuster  |  https://github.com/OJ/gobuster |  Apache License 2.0 |
| Webscreenshot | https://github.com/maaaaz/webscreenshot | GNU Lesser General Public License v3.0
| nmap | https://github.com/nmap/nmap | GNU General Public License v2.0


## Usage

```text
 ___         _ _  _           
/ __|_  _ __| (_)(_)_ __ _  _ 
\__ \ || / _  / __ \  ' \ || |
|___/\_,_\__,_\____/_|_|_\_, |
                          |__/ v{1.1.0#dev} by @screetsec 
Sud⍥my - Fast Subdmain Enumeration and Analyzer      
	 http://github.com/screetsec/sudomy

Usage: sud⍥my.sh [-h [--help]] [-s[--source]][-d[--domain=]] 

Example: sud⍥my.sh -d example.com   
         sud⍥my.sh -s Shodan,VirusTotal -d example.com
         sud⍥my.sh -pS -rS -sC -nT -sS -d example.com 

Optional Arguments:
  -a,  --all		 Running all Enumeration, no nmap & gobuster 
  -b,  --bruteforce	 Bruteforce Subdomain Using Gobuster (Wordlist: ALL Top SecList DNS) 
  -d,  --domain		 domain of the website to scan
  -h,  --help		 show this help message
  -o,  --html		 Make report output into HTML 
  -s,  --source		 Use source for Enumerate Subdomain
  -tO, --takeover	 Subdomain TakeOver Vulnerabilty Scanner
  -pS, --ping-sweep	 Check live host using methode Ping Sweep
  -rS, --resolver	 Convert domain lists to resolved IP lists without duplicates
  -sC, --status-code Get status codes, response from domain list
  -nT, --nmap-top	 Port scanning with top-ports using nmap from domain list
  -sS, --screenshot	 Screenshots a list of website
  -nP, --no-passive	 Do not perform passive subdomain enumeration 
       --no-probe	 Do not perform httprobe 

```
To user all 16 Sources and Probe for working http or https servers:
```
$ sudomy -d hackerone.com
```
To user one of more source:
```
$ sudomy -s shodan,dnsdumpster,webarchive -d hackerone.com
```
To use one or more plugins:
```
$ sudomy -pS -sC -sS -d hackerone.com
```
To user all plugins: testing hos status, http/https status code, subdomain takeover and screenshots
```
$ sudomy --all -d hackerone.com
```

To create report in HTML Format
```
$ sudomy --all -d hackerone.com --html
```


## License




**Free Software, Hell Yeah!**

