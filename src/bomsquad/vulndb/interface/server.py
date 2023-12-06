from flask import Flask, request
import sys
sys.path.append('../../../')
from bomsquad.vulndb.view.purl_vulnerabilities import query as vulnerabilities
from bomsquad.vulndb.db.connection import pool
from bomsquad.vulndb.cli.purl import get_vulns, extract_purls

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

@app.get('/health_check')
def dis_health_check():
    return 'ok'

@app.route('/purl2cve', methods=['GET', 'POST'])
def purl2cve():
    if request.method == 'GET':
        purls = request.args.get('purls')
        min_severity = request.args.get('min_severity')
        ecosystems = request.args.get('ecosystems')
        if purls:
            purls = purls.split(',')
        if ecosystems:
            ecosystems = ecosystems.split(',')
            purls = [x for x in purls if any(x.startswith(f'pkg:{prefix}') for prefix in ecosystems)]
    elif request.method == 'POST':
        sbom = request.get_json()
        purls = []
        if "components" in sbom:
            purls = extract_purls(sbom["components"])
        min_severity = None

    vulns = get_vulns(purls, min_severity=min_severity)

    if request.method == 'GET':
        return {'vulnerabilities': vulns}
    elif request.method == 'POST':
        if vulns:
            sbom['vulnerabilities'] = vulns
        return sbom

@app.route('/purl2cpe', methods=['GET'])
def purl2cpe():
    return 'purl2cpe'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000)