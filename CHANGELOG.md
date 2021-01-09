# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)

## [1.1.0] - 2019-08-24
```Initial commit```
 -  Fixing
       - Webarchive : remove email contains on list domain.
       - Docker image : add chromium webdriver for webscreenshot.

       
## [1.1.0] - 2019-08-31
 -  Update
       - Filtering list subdomain result more specific - (subdomain.txt)

## [1.1.0] - 2019-10-21
 -  Update
       - DNSDumpster update regex for retrieving csrfMiddlewaretoken values
    
## [1.1.1] - 2020-02-12
 -  Update
       - CRTSH update regex for retrieving subdomain
   
## [1.1.2] - 2020-02-15
 -  Update
       - Added Identify technologies on websites from domain list
       - Fix Some Bug and Issues

## [1.1.3] - 2020-04-03
 - Update
	- Added Plugin IP DB_PORT
	- Explain :
		- Data Collecting/Scraping open port from 3rd party (Default::Shodan), For right now just using Shodan [Future::Censys,Zoomeye] 
		- So we do not perfom active scan, who collect the port ? Third-party sites (Shodan,Zoomeye,Censys) doing that and perfom active scan and then, we just collected the port from their result   
		- More efficient and effective to collecting port from list ip on target [[ Subdomain > IP Resolver > Crawling > ASN & Open Port ]]
		- Here we can further narrow the targeting port for checking in port scanning

		- List ASN From IP List [running auto on db_port::ip_dbasn.txt]


## [1.1.4] - 2020-04-19
 - Update
	- Added Plugin for Extract URL parameter from domain (--extract-params/-ep)
	- Explain :
		- Data Collecting & Scraping URL Parameter from Passive scan (Default::Web Archive) 
		- Regex using DFA Engine (awk,sed)
		- Support and Collecting URL with multi Parameter to Fuzzing
		- Removing Duplicate Parameter & URL
		- Passive_Collecting_URLParamter.txt : This File is original Collecting URL Parameter without Parsing 
	- Fixing Bug in statement Plugin --db-port

## [1.1.5] - 2020-05-09
 - Update
	- Added New Engine selecting the good third-party sites 
		- RapidDNS 
		- AlienVault 
		- CommonCrawl
		- UrlScanIo 
	- Added Data Collecting Juicy URL & Scraping URL Parameter from Passive scan (Default::Web Archive,CommonCrawl,UrlScanIO)
		- CommonCrawl
		- WebArchive
		- UrlScanIo
	- Added Define path for outputfile (specify an output file when completed)
	- Handling Ouptut Error Entrust [403] 
	- Change the -o Argument to outputfile
	- Fix & Clean Code
	- Remove The engine (Third-party sites) to new folder for easy fixing & patch
	- Update Docker Images - Sudomy 1.1.5#dev

## [1.1.6] - 2020-06-06
 - Update
	- Added binary 3rd pkg to lib/bin for easy management/handling
        - Added New Plugin httpx  
		- Detection urls, ports, title, content-length, status-code, response-body probbing.
		- Smart auto fallback from https to http as default.

        - Added New Plugin dnsprobe                
                - Perform multiple dns queries of your choice with a list of user supplied resolvers

	- Remove the Plugin to new folder for easy fixing, update & path

## [1.1.7] - 2020-06-06
 - Update
        - Added New Plugin webanalyze
	- For using plugin apps-identifider/-ai , you can choice useing wappalyzer or webanalyze (default::wappalyzer)
		- example : ./sudomy -d bugcrowd.com -aI webanalyze 
	- Added Clouder IP Checker (Just run with argument -cf or --dnsprobe -cf )
		- IP Resolve -> Cloudfare IP Checker
	- Added Plugin Websocket Check



## [1.1.8] - 2020-06-29
- Update
        - Added New Plugin Generate Wordlist
	- Generate & make  wordlist based on collecting url resources (wayback,urlscan,commoncrawl)
		- To make that, we Extract All the paramater and path from our domain recon
	- Added New plugin to screenshot using gowitness
		- Default argument -ss (default running: gowitness)
		- You can choice another screenshot tools, like (-ss webscreeenshot)  
	- Update & Added package on "/lib/bin"
	- Added Extract Interest URL Like Document extension (pdf,docx),Javascript,Interesting path & Files
	- Fixing and Added regex to parsing url and parameter
	- Change native subdomain take over to using subjack 
	- Added to check cname (Subdomain > CNAME resolv > NXDOMAIN | Pattern matching )

## [1.1.9] - 2020-10-13
 - Update
        - Added Feature Sending notifications to a slack channel 

## [1.2.0] - 2020-12-14
 - Update
	- Fixed and update regular expresion shodan to crawling subdomain
	- Added Engine/Resources
              - DNSDB - OK
              - Spyse - Ok
              - RiskIQ/PassiveTotal - Ok
              - Facebook Cert Transparency - Ok
	- Remove Entrust Sources (Not accessible) anymore
	- Findsubdomains replace to Spyse

