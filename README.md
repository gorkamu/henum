[![forthebadge made-with-python](http://ForTheBadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
<p align='center'>
  <a href=""><img src="https://img.shields.io/badge/Version-1.0.0-brightgreen.svg?style=style=flat-square" alt="version"></a>
  <a href=""><img src="https://img.shields.io/badge/python-2-orange.svg?style=style=flat-square" alt="Python Version"></a>  
  <a href=""><img src="https://img.shields.io/github/license/Naereen/StrapDown.js.svg" alt="License"></a>
</p>

## What does this tool do?
This terminal tool allows you to perform various types of scans over a hostname.
With this terminal tool you can make network scans like DNS or Traceroute or you can also make scans of used technology or CMS

### What is a CMS?
> A content management system (CMS) manages the creation and modification of digital content. It typically supports multiple users in a collaborative environment. Some noteable examples are: *WordPress, Joomla, Drupal etc*.

## How to install it
This tool is based on python 2.7
To install henum scanner just type the following command:
```python
pip install -r requirements.txt
```
Wait until all the dependencies are downloaded and proceed with the point below.
(**PyV8 must be installed** to run)

### Aditional Dependencies
- [PyV8](https://github.com/okoye/PyV8)

Note for macos users: If you have problems installing PyV8 you can use PyV8-OS-X:
```python
pip install -e git://github.com/brokenseal/PyV8-OS-X#egg=pyv8
```
### Tested on
- macOS Catalina Version 10.15.5 (19F101) 


## How it works

## Available Scan types
- [IP Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#ip-scan)
- [DNS Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#dns-scan)
- [WHOIS Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#whois-scan)
- [Location Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#location-scan)
- [CMS Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#cms-scan)
- [Technologies Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#technologies-scan)
- [Traceroute Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#traceroute-scan)
- [Subdomains Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#subdomains-scan)
- [Reverse IP Lookup Scan](https://gitlab.com/gorkamu/henum/-/edit/master/README.md#reverse-scan)


### [IP Scan](#ip-scan)
With this type of scan you can know the IP address of a hostname.

```python
python henum.py -t example.com -s ip
```

### [DNS Scan](#dns-scan)
With this type of scan you can know the DNS records of a hostname.
The queried records are 'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'MF' and 'MD'
```python
python henum.py -t example.com -s dns
```
```json
"dns": {
      "A": [
          "avesexoticas.org. 300 IN A 37.59.219.148"
      ], 
      "SOA": [
          "avesexoticas.org. 3600 IN SOA fay.ns.cloudflare.com. dns.cloudflare.com. 2034574773 10000 2400 604800 3600"
      ], 
      "NS": [
          "avesexoticas.org. 86400 IN NS fay.ns.cloudflare.com.", 
          "avesexoticas.org. 86400 IN NS hank.ns.cloudflare.com."
      ], 
      "TXT": [
          "avesexoticas.org. 300 IN TXT \"v=spf1 +a +mx +ip4:185.162.171.100 +ip4:181.215.9.22 +include:relay.sered.net ~all\""
      ]
  }
```

### [WHOIS Scan](#whois-scan)
With this type of scan you can get the WHOIS information of a hostname.
```python
python henum.py -t example.com -s whois
```
```json
"whois": {
      "updated_date": [ ... ], 
      "status": [ ... ], 
      "name": "REDACTED FOR PRIVACY", 
      "dnssec": "unsigned", 
      "city": "REDACTED FOR PRIVACY", 
      "expiration_date": [ ... ], 
      "address": "REDACTED FOR PRIVACY", 
      "zipcode": "REDACTED FOR PRIVACY", 
      "domain_name": [
          "AVESEXOTICAS.ORG", 
          "avesexoticas.org"
      ], 
      "whois_server": "whois.registrar.eu", 
      "state": "ourense", 
      "registrar": "Hosting Concepts B.V. d/b/a Openprovider", 
      "country": "ES", 
      "name_servers": [ ... ], 
      "org": "SERED.NET", 
      "creation_date": [ ... ], 
      "emails": "abuse@registrar.eu"
  },
``` 

### [Location Scan](#location-scan)
With this type of scan you can geolocate the server's ip adress.
```python
python henum.py -t example.com -s loc
```
```json
"loc": {
      "timezone": "Europe/Paris", 
      "loc": "48.8534,2.3488", 
      "ip": "37.59.219.148", 
      "postal": "75000", 
      "org": "AS16276 OVH SAS", 
      "city": "Paris", 
      "country": "FR", 
      "region": "\u00cele-de-France", 
      "hostname": "bigovh2.gestiondeservidor.com"
  }
```

### [CMS Scan](#cms-scan)
The scan performs different attacks on CMSs based on Wordpress, Joomla, Drupal and Magento.

The most complete information today is when it detects a site made in Wordpress.

If it finds it, it tries to list the users of the backend, the version and theme used, the leaked pages, some of the plugins and if it has them, the vulnerabilities that affect each installed plugin.

```python
python henum.py -t example.com -s cms
```
```json
"cms": {
    "theme": "orbital", 
    "version": "5.3.2", 
    "users": [
        {
            "slug": "noel", 
            "link": "https://avesexoticas.org/author/noel/", 
            "id": 2, 
            "name": "Noel"
        }, 
        {
            "slug": "romu", 
            "link": "https://avesexoticas.org/author/romu/", 
            "id": 3, 
            "name": "Romu"
        }
    ], 
    "provider": "WordPress", 
    "plugins": [
        {
            "table-of-contents-plus": {
                "popular": true, 
                "last_updated": "2020-02-09T04:53:00.000Z", 
                "friendly_name": "Table of Contents Plus", 
                "latest_version": "2002", 
                "vulnerabilities": [...]
            }
        }, 
    ],
    "results": [
        "http://avesexoticas.org/wp-admin/upgrade.php", 
        "http://avesexoticas.org/readme.html"
    ]
}    
```

### [Technology Scan](#technology-scan)
With this type of scan you can get the technology used in the website
```python
python henum.py -t example.com -s technology
```
```json
"technologies": {
    "jQuery": {
        "confidence": 100, 
        "version": "", 
        "categories": [
            "javascript-frameworks"
        ]
    }, 
    "Google AdSense": {
        "confidence": 100, 
        "version": "", 
        "categories": [
            "advertising-networks"
        ]
    }
    "Google Analytics": {
        "confidence": 100, 
        "version": "", 
        "categories": [
            "analytics"
        ]
    }
}
```

### [Traceroute Scan](#traceroute-scan)
With this type of scan you can geolocate the different request package hops
```python
python henum.py -t example.com -s traceroute
```
```json
"traceroute": [
    {
        "hostname": "core-87-router", 
        "longitude": -74.6381, 
        "rtt": "1.165 ms", 
        "hop_num": 1, 
        "latitude": 40.3699, 
        "ip_address": "128.112.128.2"
    }, 
    {
        "hostname": "rtr-border-hpcrc-router.princeton.edu", 
        "longitude": -74.7013, 
        "rtt": "1.535 ms", 
        "hop_num": 2, 
        "latitude": 40.2415, 
        "ip_address": "128.112.12.110"
    }
}
```

### [Subdomains Scan](#subdomains-scan)
This scan is based on bruteforce attack so you must have patience to be completed beacuse the used wordlist contain 3297 words inside.
It detects which subdomains belongs to the hostname.
```python
python henum.py -t example.com -s subdomains
```
```json
"subdomains": [
  "www.avesexoticas.org",
  "ftp.avesexoticas.org",
  "mx.avesexoticas.org",
  ...
]
```

### [Reverse IP Lookup Scan](#reverse-scan)
This is an experimental scan based on a limited queries per day. It's still in development.
It detects which websites host the same IP address
```python
python henum.py -t example.com -s reverse_ip_lookup
```



## Sites to tests
- WP -> https://www.toyota.com.br/
- Joomla -> https://launch.joomla.org/
- magento -> http://demo-acm-2.bird.eu/
- drupal -> https://www.drupal.org/

## References
- https://github.com/robwillisinfo/cms-detector.py/blob/master/cms-detector.py
- https://github.com/Tuhinshubhra/CMSeeK/blob/master/VersionDetect/dru.py
- https://github.com/ayeowch/traceroute