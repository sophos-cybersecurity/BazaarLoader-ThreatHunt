# Threat Hunt for Bazaar backdoor phishing campaign

IOCs - 

# Sophos Central Live Discover - DataLake

Datalake query for Sophos Central Live Discover
Identify hosts where the urls in IOCs were clicked by checking process execution - https://github.com/sophos-cybersecurity/BazaarLoader-ThreatHunt/blob/master/find-clicked-users.sql

If the query times out with multiple domains, replace "LOWER('%googleapis.com%')" and run the individual queries for each domain/url

