""" --------------------------------------------------------------------------------------------------------------------
Python Tenable.io - Request an export job for all asset data:

Before you can run this, you must generate an API Key that can be used for authentication. 
You can generate the key under User Settings -> API Keys ->  'Generate' if necessary.

To run this script:
   $ python3 tio-v3-api-export-assets.py

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
   "source":"assets",
   "format":"json",
   "definition":{
      "fields":[
         "sources",
         "is_licensed",
         "ipv4_addresses",
         "display_ipv4_address",
         "first_observed",
         "is_deleted",
         "has_plugin_results",
         "is_public",
         "last_observed",
         "name",
         "Id",
         "updated",
         "host_name",
         "acr.score",
         "acr.calculated_score",
         "acr.drivers.values",
         "acr.drivers.name",
         "tags.id",
         "tags.category",
         "tags.value",
         "tags.type",
         "tenable_id",
         "aes.score",
         "aes.is_predicted",
         "aes.confidence",
         "network.id",
         "network.name",
         "system_type",
         "display_operating_system",
         "display_fqdn",
         "display_mac_address"
      ],
      "filter":{
         "and":[
            {
               "property":"is_licensed",
               "operator":"eq",
               "value": 'true'
            }
        ]
    }
   },
   "expiration":2
}

response = requests.post(url, json=payload, headers=headers)

print(response.text)
