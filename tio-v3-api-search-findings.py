import requests

url = "https://cloud.tenable.com/api/v3/findings/vulnerabilities/host/search"

payload = {
    "fields": ["asset.name", "definition.name", "state", "source", "port", "output"],
    "limit": 200
}
headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-ApiKeys": "accessKey=REPLACE_THIS_WITH_YOUR_ACCESS_KEY;secretKey=REPLACE_THIS_WITH_YOUR_SECRET_KEY"

}

response = requests.post(url, json=payload, headers=headers)

print(response.text)

