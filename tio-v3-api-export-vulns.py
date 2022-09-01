""" --------------------------------------------------------------------------------------------------------------------
Python Tenable.io - Request an export job for all vulnerability (findings) data:

Before you can run this, you must generate an API Key that can be used for authentication. 
You can generate the key under User Settings -> API Keys ->  'Generate' if necessary.

To run this script:
   $ python3 tio-v3-api-export-vulns.py

Then use "tio-v3-api-export-download.py" with the resulting UUID to fetch the results.

# ------------------------------------------------------------------------------------------------------------------ """

import requests

url = "https://cloud.tenable.com/api/v3/exports/jobs"

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-ApiKeys": "accessKey=REPLACE_THIS_WITH_YOUR_ACCESS_KEY;secretKey=REPLACE_THIS_WITH_YOUR_SECRET_KEY"
}


payload = {
   "name":"TEST API",
   "source":"findings/vulnerabilities/host",
   "format":"json",
   "definition":{
      "fields":[
         "severity",
         "definition.name",
         "definition.id",
         "definition.family",
         "port",
         "protocol",
         "definition.vpr.score",
         "state",
         "last_observed",
         "id",
         "definition.patch_published",
         "definition.vpr.drivers_threat_recency_low",
         "definition.vpr.drivers_threat_recency_high",
         "definition.vpr.drivers_threat_intensity",
         "definition.vpr.drivers_exploit_code_maturity",
         "definition.vpr.drivers_age_of_vulns_low",
         "definition.vpr.drivers_age_of_vulns_high",
         "definition.vpr.drivers_product_coverage",
         "definition.vpr.drivers_cvss3_impact_score",
         "definition.vpr.drivers_threat_sources",
         "definition.description",
         "definition.solution",
         "definition.see_also",
         "definition.vulnerability_published",
         "definition.cpe",
         "definition.exploitability_ease",
         "definition.plugin_published",
         "definition.plugin_updated",
         "definition.plugin_version",
         "definition.cvss2.base_score",
         "definition.cvss2.base_vector",
         "definition.cvss2.temporal_vector",
         "definition.cvss3.base_score",
         "definition.cvss3.base_vector",
         "definition.cvss3.temporal_score",
         "definition.cvss3.temporal_vector",
         "asset_inventory",
         "default_account",
         "definition.exploited_by_malware",
         "definition.exploited_by_nessus",
         "definition.in_the_news",
         "definition.malware",
         "definition.unsupported_by_vendor",
         "definition.stig_severity",
         "output",
         "risk_modified",
         "scan.id",
         "asset.network_id",
         "asset.tags",
         "asset.name",
         "asset.display_ipv4_address",
         "asset.display_ipv6_address",
         "asset.id",
         "last_seen",
         "definition.type",
         "definition.severity",
         "definition.cvss2.temporal_score",
         "first_observed"
      ],
      "filter":{
         "and":[
            {
               "property":"severity",
               "operator":"eq",
               "value":[
                  4
               ]
            },
            {
               "property":"state",
               "operator":"eq",
               "value":[
                  "ACTIVE",
                  "RESURFACED",
                  "NEW"
               ]
             }
        ]
    }
   },
   "expiration":2
}

response = requests.post(url, json=payload, headers=headers)

print(response.text)