import requests

url = "https://cloud.tenable.com/api/v3/assets/search"

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-ApiKeys": "accessKey=REPLACE_THIS_WITH_YOUR_ACCESS_KEY;secretKey=REPLACE_THIS_WITH_YOUR_SECRET_KEY"
}

try:
    asset_id = sys.argv[1]
except:
    asset_id = input("Please provide your asset UUID: ")

if len(asset_id) != 36:
    print("This is an invalid asset UUID!")
    sys.exit()

#Example asset_id = "e39a7f5d-e2aa-457b-9467-bda428fb1926"
# 7fe14b89-37cc-4eab-9b24-6e65b191f2a4

payload = {
  "filter": {
    "and": [
      {
        "property": "id",
        "operator": "eq",
        "value": [
          asset_id
        ]
      },
      {
        "property": "is_licensed",
        "operator": "eq",
        "value": 'true'
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
