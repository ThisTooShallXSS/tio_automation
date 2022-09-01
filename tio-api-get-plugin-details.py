
import requests

url = "https://cloud.tenable.com/plugins/plugin/500001"

headers = {
    "Accept": "application/json",
    "X-ApiKeys": "accessKey=REPLACE_THIS_WITH_YOUR_ACCESS_KEY;secretKey=REPLACE_THIS_WITH_YOUR_SECRET_KEY"
}

response = requests.get(url, headers=headers)

print(response.text)