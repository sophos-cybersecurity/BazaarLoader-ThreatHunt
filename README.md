# Threat Hunt for Bazaar backdoor phishing campaign

IOCs - https://github.com/sophos-cybersecurity/BazaarLoader-ThreatHunt/blob/master/IOC.csv 

# Technical Analysis by Sophos Labs - https://twitter.com/SophosLabs/status/1456391375998619650

# Naked Security article - https://nakedsecurity.sophos.com/2021/11/05/customer-complaint-email-scam-preys-on-your-fear-of-getting-into-trouble-at-work/

# Sophos Central Live Discover Query

Datalake query for Sophos Central Live Discover
* Identify hosts where the urls in IOCs were clicked by checking process execution - https://github.com/sophos-cybersecurity/BazaarLoader-ThreatHunt/blob/master/find-clicked-users.sql

* _Note:_ _Due to query timeout for multiple domains/urls, replace "LOWER('%googleapis.com%')" and run the individual queries for each domain/url_

