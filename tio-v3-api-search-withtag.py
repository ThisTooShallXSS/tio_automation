import requests

url = "https://cloud.tenable.com/api/v3/assets/host/search"

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-ApiKeys": "accessKey=REPLACE_THIS_WITH_YOUR_ACCESS_KEY;secretKey=REPLACE_THIS_WITH_YOUR_SECRET_KEY"
}

try:
    tag_uuid = sys.argv[1]
except:
    tag_uuid = input("Please provide your tag UUID:")

if len(tag_uuid) != 36:
    print("This is an invalid tag UUID!")
    sys.exit()

#Example tag_uuid = "01ed44a1-4dbf-449a-aff9-fd9969dae1f1"

payload = {
  "filter": {
    "and": [
      {
        "property": "tags",
        "operator": "eq",
        "value": [
          tag_uuid
        ]
      },
      {
        "property": "types",
        "operator": "eq",
        "value": "host"
      }
    ]
  },
  "limit": 200
}

response = requests.post(url, json=payload, headers=headers)

print(response.text)
