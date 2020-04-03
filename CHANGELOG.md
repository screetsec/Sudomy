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
	- Explain about IP DB_PORT 
	- Data Collecting/Scraping open port from 3rd party (Default::Shodan), For right now just using Shodan [Future::Censys,Zoomeye] 
	- So we do not perfom active scan, who collect the port ? Third-party sites (Shodan,Zoomeye,Censys) doing that and perfom active scan and then, we just collected the port from their result   
	- More efficient and effective to collecting port from list ip on target [[ Subdomain > IP Resolver > Crawling > ASN & Open Port ]]
	- Here we can further narrow the targeting port for checking in port scanning

	- List ASN From IP List [running auto on db_port::ip_dbasn.txt]


