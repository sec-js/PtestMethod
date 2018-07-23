***************************************************************
Intelligence Gathering
***************************************************************

This post (always Work in Progress) lists technical steps which one can follow while gathering information about an organization. 

Suppose, we are tasked with an external/ internal penetration test of a big organization with DMZ, Data centers, Telecom network etc. Moreover, the only information that we know at this moment is the company name and/or it’s domain name such as example.com 




.. _question:

What are the

* Domain/ subdomains present? (like example.com -- domain; ftp.example.com -- subdomain)
* IP Addresses/ Network ranges/ ASN Number(s) assigned?
* Different Services (open ports) running on those IP Addresses?
* Email addresses or People working for the organization?
* Different Operating Systems/ Software used in the organization?

Additionally it is also interesting to know if there have been any security breaches
in the past.

We might be able to compromise user credential(s) or running vulnerable service(s) and get 
inside the internal network of the organization.

Fingerprinting
==============

We can either do **Passive fingerprinting** (learning more about the company, without them knowing it) or **Active fingerprinting** (process of transmitting packets to a remote host and analysing corresponding replies (which very likely will be logged)). 

**Passive fingerprinting** and **Active fingerprinting** can be done by using various methods such as:

+------------------------------------------------+--------------------------------------+
|         Passive Fingerprinting                 |       Active Fingerprinting          |
+================================================+======================================+
| - whois                                        | - Finding DNS, MX, AAAA, A           |
+------------------------------------------------+--------------------------------------+
| - ASN Number                                   | - DNS Zone Transfer(s)               |
+------------------------------------------------+--------------------------------------+
| - Enumeration with Domain Name                 | - SRV Records                        |
+------------------------------------------------+--------------------------------------+
| - Publicly available scans of IP Addresses     | - Port Scanning                      |
+------------------------------------------------+--------------------------------------+
| - Reverse DNS Lookup using External Websites   |                                      |
+------------------------------------------------+--------------------------------------+

Do you remember from earlier? We need to find answers to 

+---------------------------------------------------------------+-------------------------------------------------------+
|     Questions (What are the)                                  | Answer                                                |
+===============================================================+=======================================================+
| Different domain/ subdomains present?                         | whois, DNS-MX/AAAA/A/SRV, Enumeration with Domain Name|
+---------------------------------------------------------------+-------------------------------------------------------+
| Different IP Address/ Network ranges/ ASN Number assigned?    | DNS, ASN-Number, DNS-Zone-Transfer                    |
+---------------------------------------------------------------+-------------------------------------------------------+
| Different Services/ Ports running on those IP Addresses?      | Public Scans of IP/ Port Scanning                     |
+---------------------------------------------------------------+-------------------------------------------------------+
| Email addresses or People working in the organization?        | harvestor, LinkedIn                                   |
+---------------------------------------------------------------+-------------------------------------------------------+
| What are the different Operating Systems/ Software used?      | FOCA                                                  |
+---------------------------------------------------------------+-------------------------------------------------------+
| Any breaches which happened in the organization?              |                                                       |
+---------------------------------------------------------------+-------------------------------------------------------+

The active and passive fingerprinting would help us to get those answers!

Passive Fingerprinting:
=======================

Whois
-----
Whois provides information about the registered users or assignees of an Internet resource, such as a Domain name, an IP address block, or an autonomous system. 

whois acts differently when given an IP address then a domain name.

* For a Domain name, it just provides registrar name etc.
* For a IP address, it provides the net-block, ASN Number etc.

::

  whois <Domain Name/ IP Address>  
  -H Do not display the legal disclaimers some registries like to show you.                                
      
Googling for

:: 

  "Registrant Organization" inurl: domaintools

Also helps for to search for new domains registered by the same organization. "Registrant Organization" is present in the output of whois. 
This technique was used by person who compromised FinFisher in his `writeup <http://pastebin.com/raw/cRYvK4jb>`__.

.. Todo :: Add example so people don't have to (re)read or skim through the pastebin article  

ASN Number
----------

We could find the AS Number that participates in the Border Gateway Protocol (BGP) used by particular organization which could further inform about the IP address ranges used by the organization. An ASN Number could be found by using Team CMRU whois service

:: 
    
  whois -h whois.cymru.com " -v 216.90.108.31"                         |
      
If you want to do bulk queries refer @ `IP-ASN-Mapping-Team-CYMRU <http://www.team-cymru.org/IP-ASN-mapping.html>`_

Hurricane Electric Internet Services also provide a website `BGPToolkit <http://bgp.he.net>`__ which provides your IP Address ASN or search function by Name, IP address etc. It also provides AS Peers which might help in gathering more information about the company in terms of its neighbors.

.. Todo ::  Commandline checking of subnet and making whois query efficient.

Recon-ng <https://bitbucket.org/LaNMaSteR53/recon-ng/wiki/Usage%20Guide>
^^^^^^^^


* use recon/domains-hosts/bing\_domain\_web : Harvests hosts from Bing.com by using the site search operator.
* use recon/domains-hosts/google\_site\_web : Harvests hosts from google.com by using the site search operator.
* use recon/domains-hosts/brute\_hosts : Brute forces host names using DNS.
* use recon/hosts-hosts/resolve : Resolves the IP address for a host.
* use reporting/csv : Creates a CSV file containing the specified harvested data.


The Harvester <https://github.com/laramies/theHarvester>
^^^^^^^^^^^^^

The harvester provides email addresses, virtual hosts, different domains, shodan results etc. for the domain. It provides really good results, especially if you combine with shodan results as it may provide server versions and what's OS is running on a provided IP address.

:: 

  Usage: theharvester options      
     -d: Domain to search or company name                          
     -b: data source: google, googleCSE, bing, bingapi, pgp        
                      linkedin, google-profiles, people123, jigsaw,
                      twitter, googleplus, all
     -v: Verify host name via dns resolution and search for virtual hosts                              |
     -f: Save the results into an HTML and XML file 
     -c: Perform a DNS brute force for the domain name             
     -t: Perform a DNS TLD expansion discovery
     -e: Use this DNS server   
     -h: use SHODAN database to query discovered hosts             |
         



Spiderfoot <http://www.spiderfoot.net/download/>
^^^^^^^^^^^^^

SpiderFoot is a reconnaissance tool that automatically queries over 100 public data sources (OSINT) to gather intelligence on IP addresses, domain names, e-mail addresses, names and more. You simply specify the target you want to investigate, pick which modules to enable and then SpiderFoot will collect data to build up an understanding of all the entities and how they relate to each other.



Enumeration with Domain Name (e.g. example.com) using external websites
-----------------------------------------------------------------------

If you have domain name you could use

DNS Dumpster API
^^^^^^^^^^^^^^^^

We can utilize DNS Dumpster's API to know the various sub-domain related to a domain.

:: 
       
  curl -s http://api.hackertarget.com/hostsearch/?q=example.com > hostsearch    

and the various dns queries by

:: 

  curl -s http://api.hackertarget.com/dnslookup/?q=example.com > dnslookup      
  
  
  .. Todo :: Combine these results with recon-ng, spiderfoot and DNS Dumpsters and create one csv with all results.

Google Dorks (search operators)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* **site**: Get results from certain sites or domains.
* **filetype:suffix**: Limits results to pages whose names end in suffix. The suffix is anything following the last period in the file name of the web page. For example: filetype:pdf
* **allinurl/ inurl**: Restricts results to those containing all the query terms you specify in the URL. For example, [ allinurl: google faq ] will return only documents that contain the words “google” and “faq” in the URL, such as “www.google.com/help/faq.html”.
* **allintitle/ intitle**: Restricts results to those containing all the query terms you specify in the title.

Three good places to refer are `Search Operators <https://support.google.com/websearch/answer/2466433>`__, `Advanced Operators <https://sites.google.com/site/gwebsearcheducation/advanced-operators>`__ and `Google Hacking Database <https://www.exploit-db.com/google-hacking-database/>`__.

Other Tools
^^^^^^^^^^^

* `SearchDiggityv3 <http://www.bishopfox.com/resources/tools/google-hacking-diggity/attack-tools/>`__ is Bishop Fox’s MS Windows GUI application that serves as a front-end to the most recent versions of our Diggity tools: GoogleDiggity, BingDiggity, Bing, LinkFromDomainDiggity, CodeSearchDiggity, DLPDiggity, FlashDiggity, MalwareDiggity, PortScanDiggity, SHODANDiggity, BingBinaryMalwareSearch, and NotInMyBackYard Diggity.


Publicly available scans of IP Addresses
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `Exfiltrated <https://exfiltrated.com/>`__ provides the scans from the 2012 Internet Census. It would provide the IP address and the port number running at the time of scan in the year 2012.
* `Shodan <https://www.shodan.io/>`__: provides the same results may be with recent scans. You need to be logged-in. Shodan CLI is available at `Shodan Command-Line Interface <https://cli.shodan.io/>`__

Shodan Queries 

:: 

  title   : Search the content scraped from the HTML tag
  html    : Search the full HTML content of the returned page
  product : Search the name of the software or product identified in the banner
  net     : Search a given netblock (example: 204.51.94.79/18)
  version : Search the version of the product
  port    : Search for a specific port or ports
  os      : Search for a specific operating system name
  country : Search for results in a given country (2-letter code)
  city    : Search for results in a given city


* `Censys <https://censys.io/>`_ is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet. Driven by Internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, websites, and certificates are configured and deployed. A good feature is the Query metadata which tells the number of Http, https and other protocols found in the IP network range.

 Censys.io queries
   
 :: 

  ip:192.168.0.0/24 -- CIDR notation

           
Reverse DNS Lookup using External Websites
------------------------------------------

Even after doing the above, sometimes we miss few of the domain name. Example: Recently, In  one of our engagement, the domain name was example.com and the asn netblock was 192.168.0.0/24. We did recon-ng, theharvester, DNS reverse-lookup via nmap. Still, we missed few of the websites hosted on same netblock but with different domain such as example.in. We can find such entries by using ReverseIP lookup by

DomainTools Reverse IP Lookup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
`Reverse IP Lookup by Domaintools <http://reverseip.domaintools.com>`__: Domain name search tool that allows a wildcard search, monitoring of WHOIS record changes and history caching, as well as Reverse IP queries.

PassiveTotal
^^^^^^^^^^^^
`Passive Total <https://community.riskiq.com//>`__ : A threat-analysis platform created for analysts, by analysts.

Server-Sniff
^^^^^^^^^^^^

`Server Sniff <http://serversniff.net.ipaddress.com/>`__ : A website providing IP Lookup, Reverse IP services.

Robtex
^^^^^^
`Robtex <https://www.robtex.com/>`__ : Robtex is one of the world's largest network tools. At robtex.com, you will find everything you need to know about domains, DNS, IP, Routes, Autonomous Systems, etc. There's a nmap nse `http-robtex-reverse-ip <https://nmap.org/nsedoc/scripts/http-robtex-reverse-ip.html>`__ which can be used to find the domain/ website hosted on that ip.

::
 
  nmap --script http-robtex-reverse-ip --script-args http-robtex-reverse-ip.host='XX.XX.78.214'
  Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-20 21:39 IST
  Pre-scan script results:
  | http-robtex-reverse-ip: 
  |   xxxxxxindian.com
  |_  www.xxxxxindian.com

.. _active_fingerprinting:       
  
Active Fingerprinting
=====================

* For Scanning the Network see Nmap Documenation <https://nmap.org/>

* For basic and essential tools, take a look at : host dig, nslookup,...

Exploring the Network Further
------------------------------

By now, we would have information about what ports are open and possibly what services are running on them. Further, we need to explore the various options by which we can get more information.
       
Gathering Screenshots for http* services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are four ways (in my knowledge to do this):

* **http-screenshot NSE**: Nmap has a NSE script `http-screenshot <https://github.com/SpiderLabs/Nmap-Tools/blob/master/NSE/http-screenshot.nse>`__ This could be executed while running nmap. It uses the wkhtml2image tool. Sometimes, you may find that running this script takes a long time. It might be a good idea to gather the http\* running IP, Port and provide this information to wkhtml2image directly via scripting. You do have to install wkhtml2image and test with javascript disabled and other available options.

* **httpscreenshot** from breenmachine: `httpscreenshot <https://github.com/breenmachine/httpscreenshot>`__ is a tool for grabbing screenshots and HTML of large numbers of websites. The goal is for it to be both thorough and fast which can sometimes oppose each other.

* **Eyewitness** from Chris Truncer: `EyeWitness <https://github.com/ChrisTruncer/EyeWitness>`__ is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.

* Another method is to use `html2image <https://code.google.com/p/java-html2image/>`__ which is a simple Java library which converts plain HTML markup to an image and provides client-side image-maps using html element.

* **RAWR: Rapid Assessment of Web Resources**: `RAWR <https://bitbucket.org/al14s/rawr/wiki/Home>`__ provides with a customizable CSV containing ordered information gathered for each host, with a field for making notes/etc.; An elegant, searchable, JQuery-driven HTML report that shows screenshots, diagrams, and other information. A report on relevant security headers. In short, it provides a landscape of your webapplications. It takes input from multiple formats such as Nmap, Nessus, OpenVAS etc.
      
Information Gathering for http* Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `WhatWeb <http://www.morningstarsecurity.com/research/whatweb>`__ recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded device. `Tellmeweb <https://www.aldeid.com/wiki/Tellmeweb>`__ is a ruby script which reads a Nmap Gnmap file and runs whatweb against all identified open http and https ports. A `WhatWeb Result Parser <https://github.com/stevecoward/whatweb-parser>`__ has also been written which converts the results to CSV format. More information about advanced usage can be found at `Whatweb Advance Usage <https://github.com/urbanadventurer/WhatWeb/wiki/Advanced-Usage>`__.
      
* `Wapplyzer <http://wappalyzer.com>`__ is a Firefox plug-in. There are four ways (in my knowledge to do this) be loaded on browser. It works completely at the browser level and gives results in the form of icons.
* `W3Tech <http://w3techs.com/>`__ is another Chrome plug-in which provides information about the usage of various types technologies on the web. It tells which web technologies are being used based on the crawling it has done. So example.com, x1.example.com, x2.example.com will show the same technologies as the domain is same (which is not correct).
* `ChromeSnifferPlus <https://github.com/justjavac/ChromeSnifferPlus>`__ is another chrome extension which identifies the different web-technologies used by a website.      
* `BuiltWith <http://builtwith.com/>`__ is another website which provides a good amount of information about the different technologies used by website.



Attack Surface Area - Reconnaissance Tools
==========================================

Aquatone: A tool for domain flyovers
------------------------------------

`Aquatone <https://github.com/michenriksen/aquatone>`_ is a set of tools for performing reconnaissance on domain names. It can discover subdomains on a given domain by using open sources as well as the more common subdomain dictionary brute force approach. After subdomain(s) discovery, AQUATONE can scan the identified hosts (subdomains) for common web ports and HTTP headers, HTML bodies and screenshots can be gathered and consolidated into a report for easy analysis of the attack surface. A detailed blog is available at `AQUATONE: A tool for domain flyovers <http://michenriksen.com/blog/aquatone-tool-for-domain-flyovers/>`_

DataSploit
----------

The `Datasploit <https://github.com/DataSploit/datasploit>`_ tool performs various OSINT techniques, aggregates all the raw data, and returns the gathered data in multiple formats.

Functional Overview:

* Performs OSINT on a domain / email / username / phone and find out information from different sources.
* Correlates and collaborate the results, shows them in a consolidated manner.
* Tries to figure out credentials, api-keys, tokens, subdomains, domain history, legacy portals, etc. related to the target.
* Use specific script/ launch automated OSINT to consolidate data.
* Performs Active Scans on collected data.
* Generates HTML, JSON reports along with text files.

Spiderfoot
----------

`SpiderFoot <http://www.spiderfoot.net/>`_ is an open source intelligence automation tool. Its goal is to automate the process of gathering intelligence about a given target, which may be an IP address, domain name, hostname or network subnet. SpiderFoot can be used offensively, i.e. as part of a black-box penetration test to gather information about the target or defensively to identify what information your organization is freely providing for attackers to use against you.

Intrigue.io
-----------

`Intrigue <https://github.com/intrigueio/intrigue-core>`_ makes it easy to discover information about the attack surface connected to the Internet. Intrigue utilizes common OSINT sources via “tasks” to create “entities”. Each discovered entity can be used to discover more information, either automatically or manually.


Ivre: A tool for domain flyovers
---------------------------------

`IVRE <http://www.ivre.rocks/>`_ is an open-source framework for network recon. It relies on open-source well-known tools (Nmap, Zmap, Masscan, Bro and p0f) to gather data (network intelligence), stores it in a database (MongoDB), and provides tools to analyze it.

It includes a Web interface aimed at analyzing Nmap scan results (since it relies on a database, it can be much more efficient with huge scans than a tool like Zenmap, the Nmap GUI, for example).

### How to tune Nmap in ivre ?

/etc/ivre.conf

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
NMAP_SCAN_TEMPLATES["noping"]= {
     "traceroute": "True",
     "osdetect": "True",
     "pings": "n",
     "ports": "more",
     "resolve": "1",
     "extra_options": ['-T2', '-sC'],
     "verbosity": 2,
     "host_timeout": "15m",
     "script_timeout": "2m",  # default value: None
     "scripts_categories": ['default', 'discovery', 'auth'],
     "scripts_exclude": ['broadcast', 'brute', 'dos', 'exploit', 'external', 'fuzzer',
                            'intrusive'],  # default value: None
   # "scripts_force": None,
# "extra_options": None,
}

NMAP_SCAN_TEMPLATES["aggressive"] = NMAP_SCAN_TEMPLATES["default"].copy()
NMAP_SCAN_TEMPLATES["aggressive"].update({
     "host_timeout": "30m",
     "script_timeout": "5m",
     "scripts_categories": ['default', 'discovery', 'auth', 'brute',
                            'exploit', 'intrusive'],
     "scripts_exclude": ['broadcast', 'external']
 })
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

### How to get all CN certs from ivre ?

**From Scancli**

~~~~
 ivre scancli --distinct ports.scripts.ssl-cert.subject.
~~~~

OR

~~~~
 ivre scancli --distinct ports.scripts.ssl-cert.subject | python -c "import ast,json,sys
for l in sys.stdin: print(json.dumps(ast.literal_eval(l)))" | jq .commonName
~~~~

**From Python API**

~~~~
 db.nmap.searchscript(name='ssl-cert', values={'subject.commonName': {'$exists': True}}) or, preferably 
~~~~

OR

~~~~
db.nmap.searchscript(name='ssl-cert', values={'subject.commonName': re.compile('')} 
~~~~

> Not formally the same meaning, but the latter is more portable and should work with PostgreSQL backend.

MyGoTo
==============

1. Launch Spidefoot, Recon-ng, dicsover
2. Launch Ivre on the network with T0 ot proxycanon
3. Determine vulnerabilities and threat vectors
4. Check Possibility of the attacks
5. Determine what kind of Info can be compromised
6. Report

>  In case the enterprise wants to determine it's blue team capacities check multiple attack vectors and check if you get discovered.
>
