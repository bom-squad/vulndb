import requests
import json

url = 'http://172.17.0.2:4000/purl2cve?purls=pkg:golang/golang.org/x/net@v0.12.0,pkg:pypi/golang.org/x/net@v0.11.0&ecosystems=go&min_severity=HIGH'

response = requests.get(url)
if response.status_code == 200:
    print('Request was successful.')
    j = json.loads(response.text)
    print(j)
else:
    print(f'Request failed with status code {response.status_code}')