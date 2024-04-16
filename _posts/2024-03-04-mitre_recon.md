---
layout: post
title: mitre attack recon method
date: 2024-03-04
description: mitre recon notes
categories: bhatagem recon
---

## Mitre Recon

### 1 - Gather Victim Org Information

- https://attack.mitre.org/techniques/T1591/
- Determine Physical Locations
- Business Relationships
- Identify Business Tempo
- Identify Roles 

### 2 - Gather Victim Identity Information

https://attack.mitre.org/techniques/T1589/

Credentials
- https://attack.mitre.org/techniques/T1589/001/

Email Address
- https://attack.mitre.org/techniques/T1589/002/

Employee Names
- https://attack.mitre.org/techniques/T1589/003/


### 3 - Search Open Websites/Domains

https://attack.mitre.org/techniques/T1593/

- https://cyware.com/news/how-hackers-exploit-social-media-to-break-into-your-company-88e8da8e
- https://securitytrails.com/blog/google-hacking-techniques
- https://www.exploit-db.com/google-hacking-database

Social media
- https://attack.mitre.org/techniques/T1593/001/

Code Repositories (github search)


### 4 - Search Open Technical Databases 

https://attack.mitre.org/techniques/T1596/

- some whois
- passive dns - https://dnsdumpster.com/
- digital certs - https://www.sslshopper.com/ssl-checker.html
- CDNs
- shodan and others...


### 5 - Search Victim-Owned Websites 

https://attack.mitre.org/techniques/T1594/



### 6 - Search Closed Sources

Threat Intel Vendors
- https://d3security.com/blog/10-of-the-best-open-source-threat-intelligence-feeds/
- https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/

     

### 7 - Gather Victim Network Information 

FQDNs
- https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/

Network Trust Dependencies 
- https://www.slideshare.net/rootedcon/carlos-garca-pentesting-active-directory-forests-rooted2019

IP Addresses
- https://attack.mitre.org/techniques/T1590/005/

Network Security Appliances
- https://nmap.org/book/firewalls.html



### 8 - Gather Victim Host Information 

Software
- https://attack.mitre.org/techniques/T1592/002/



### 9 - Phishing for Information 

https://attack.mitre.org/techniques/T1598/



### 10 - Active Scanning 

Scanning IP Blocks 

Vulnerability Scanning  https://attack.mitre.org/techniques/T1595/002/

Wordlist Scanning (brute-force)
  - https://github.com/clarketm/s3recon
  - https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/

