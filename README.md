# Sudomy
[![License](https://img.shields.io/badge/license-MIT-red.svg)](https://opensource.org/licenses/MIT)  [![Version](https://img.shields.io/badge/Release-1.1.0-blue.svg?maxAge=259200)]()   [![Build](https://img.shields.io/badge/Supported_OS-Linux-yellow.svg)]() [![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/screetsec/sudomy/issues)
### Subdomain Enumeration & Analysis
![ff](https://user-images.githubusercontent.com/17976841/63212795-b8d57300-c133-11e9-882a-f604d67819cc.png)

***Sudomy*** is a subdomain **enumeration** tool, created using a bash script, to **analyze** domains and **collect** subdomains in **fast** and **comprehensive** way.

# Features !
##### For recent time, ***Sudomy*** has these 9 features:
-  **Easy, light, fast and powerful**. Bash script is available by default in almost all Linux distributions. By using bash script **multiprocessing** feature, all processors will be **utilized** optimally.
-  Subdomain enumeration process can be achieved by using **active** method or **passive** method
    - **Active Method**
        - ***Sudomy*** utilize **Gobuster** tools because of its **highspeed performance** in carrying out **DNS Subdomain Bruteforce** attack (**wildcard support**). The **wordlist** that is used comes from **combined SecList (Discover/DNS)** lists which contains around **3 million** entries

    - **Passive Method**
        - By **selecting** the **third-party** sites, the **enumeration process** can be **optimized**. More **results** will be **obtained** with **less time** require. ***Sudom***y can collect data from these  well-curated **16 third-party sites** :
    
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
- Test the **list of collected subdomain** and probe for **working http or https servers**. This feature uses a third-party tool, [httprobe](https://github.com/tomnomnom/httprobe "httprobe") .
- Subdomain **availability test based** on **Ping Sweep** and/or by getting **HTTP status code**.
- The ability to **detect virtualhost** (several subdomains which resolve to single IP Address). ***Sudomy*** **will resolve the collected subdomains to IP addresses**, then  **classify them if several subdomains resolve to single IP address**. This feature will be **very useful** for the next **penetration testing/bug bounty** process. For ***instance, in port scanning, single IP address won’t be scanned repeatedly***
- Performed **port scanning** from collected **subdomains/virtualhosts IP Addresses**
- Testing **Subdomain TakeOver** attack
- Taking **Screenshots** of subdomains
- Report output in **HTML** or **CSV** format

# How Sudomy Works
***Sudomy*** is using cURL library in order to get the HTTP Response Body from third-party sites to then execute the regular expression to get subdomains. This process fully leverages multi processors, more subdomains will be collected with less time consumption.  
# Comparison
The following are the results of passive enumeration DNS testing of ***Sublist3r, Subfinder***, and ***Sudomy***. The domain that is used in this comparison is ***bugcrowd.com***. 
