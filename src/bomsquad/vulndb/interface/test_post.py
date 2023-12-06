import requests
import json
import os

url = 'http://172.17.0.2:4000/purl2cve'

sbom_file_path = '0xERR0R_blocky_syft_cyclonedx.json'

with open(sbom_file_path, 'r') as json_file:
    data = json.load(json_file)

# Set the headers to indicate that you're sending JSON data
headers = {'Content-Type': 'application/json'}
json_data = json.dumps(data)

# Send the POST request
response = requests.post(url, data=json_data, headers=headers)

# Check the response
if response.status_code == 200:
    print('Request was successful.')
    j = json.loads(response.text)
    print(j)
else:
    print(f'Request failed with status code {response.status_code}')