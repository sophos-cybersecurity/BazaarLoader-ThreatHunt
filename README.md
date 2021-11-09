# Threat Hunt for Bazaar backdoor phishing campaign

IOCs - https://github.com/sophos-cybersecurity/BazaarLoader-ThreatHunt/blob/master/IOC.csv 

# Sophos Central Live Discover Query

Datalake query for Sophos Central Live Discover
* Identify hosts where the urls in IOCs were clicked by checking process execution - https://github.com/sophos-cybersecurity/BazaarLoader-ThreatHunt/blob/master/find-clicked-users.sql

* _Note:_ _Due to query timeout for multiple domains/urls, replace "LOWER('%googleapis.com%')" and run the individual queries for each domain/url_

