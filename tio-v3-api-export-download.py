""" --------------------------------------------------------------------------------------------------------------------
Python Tenable.io - Download a requested export job:

You must run either of the example scripts "tio-v3-api-export-assets.py" or "tio-v3-api-export-vulns.py" to get the 
UUID necessary for this script. You can pass the UUID in to this script as an argument, or just run the script.

To run this script:
   $ python3 tio-v3-api-export-download.py

You can also directly pass in the UUID:
   $ python3 tio-v3-api-export-download.py <export_uuid_here>
   $ python3 tio-v3-api-export-download.py 4db49aa5-90c4-4820-a511-750d66715d42

# ------------------------------------------------------------------------------------------------------------------ """

import requests
import os
import sys

headers = {
    "Accept": "application/octet-stream",
    "X-ApiKeys": "accessKey=REPLACE_THIS_WITH_YOUR_ACCESS_KEY;secretKey=REPLACE_THIS_WITH_YOUR_SECRET_KEY"
}

try:
    export_uuid = sys.argv[1]
except:
    export_uuid = input("Please provide your export UUID: ")

if len(export_uuid) != 36:
    print("This is an invalid export UUID!")
    sys.exit()

# Example url = "https://cloud.tenable.com/api/v3/exports/jobs/104a3108-f952-4a6b-b7b9-ff268e67d56f/content"

formatted_url = "https://cloud.tenable.com/api/v3/exports/jobs/" + export_uuid + "/content"

response = requests.get(formatted_url, headers=headers)

print(response.text)
