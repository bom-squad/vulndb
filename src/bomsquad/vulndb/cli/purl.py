import logging

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from bomsquad.vulndb.view.purl_vulnerabilities import query as vulnerabilities
import os
import json
from json.decoder import JSONDecodeError
from bomsquad.vulndb.db.connection import pool

logger = logging.getLogger(__name__)

console = Console(record=True)

purl_app = typer.Typer(name="purl")

def extract_purls(data):
    purls = set()
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "purl":
                purls.add(value)
            purls.update(extract_purls(value))
    elif isinstance(data, list):
        for item in data:
            purls.update(extract_purls(item))
    return purls

def is_supported_ecosystem(purl):
    supported_prefixes = ["pkg:pypi", "pkg:maven", "pkg:go", "pkg:nuget", "pkg:cargo"]
    return any(purl.startswith(prefix) for prefix in supported_prefixes)

def extract_vector(input_str):
    parts = input_str.split('/')
    for part in parts:
        if any(part.startswith(prefix) for prefix in ["CVSS:3.1", "CVSS:3.0", "CVSS:2"]):
            return '/'.join(parts[1:])
    return input_str

def severity_larger_or_equal(base_severity, min_severity):
    severity_levels = [None, "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    base_severity_index = severity_levels.index(base_severity)
    min_severity_index = severity_levels.index(min_severity)
    return base_severity_index >= min_severity_index

def get_ratings(metrics, min_severity=None):
    ratings = []
    for metric_key, metric_values in metrics.items():
        for metric_dict in metric_values:
            vector = extract_vector(metric_dict['cvssData']['vectorString'])
            base_score = metric_dict['cvssData']['baseScore']
            base_severity = metric_dict['cvssData'].get('baseSeverity')
            if metric_key == 'cvssMetricV40':
                method, cvss_ver = 'CVSSv4', "4.0"
            elif metric_key == 'cvssMetricV31':
                method, cvss_ver = 'CVSSv31', "3.1"
            elif metric_key == 'cvssMetricV30':
                method, cvss_ver = 'CVSSv3', "3.0"
            elif metric_key == 'cvssMetricV2':
                method, cvss_ver = 'CVSSv2', "2.0"
            else:
                method, cvss_ver = 'other', None

            if severity_larger_or_equal(base_severity, min_severity):
                rating = {
                    "source": {
                        "name": "NVD",
                        "url": f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector={vector}&version={cvss_ver}"
                    },
                    "score": str(base_score),
                    "severity": base_severity,
                    "method": method,
                    "vector": str(vector)
                }
                ratings.append(rating)
    return ratings

def get_cwes(weaknesses):
    cwes = set()
    for weakness in weaknesses:
        if 'description' in weakness:
            for desc in weakness['description']:
                if 'value' in desc and desc['value'].startswith('CWE-'):
                    try:
                        cwe_number = desc['value'].replace('CWE-', '')
                        cwes.add(int(cwe_number))
                    except ValueError:
                        pass
    return list(cwes)

def get_description(descriptions):
    return ' '.join(f'({desc["lang"]}) {desc["value"]}' for desc in descriptions if "value" in desc and "lang" in desc)

def get_source(cve_id):
    source_name = "NVD"
    source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return {"name": source_name, "url": source_url}

def get_vulns(purls, min_severity=None):
    cve_ids = set()
    dict_cve_ids_to_bom_ref = {}
    for purl in purls:
        if is_supported_ecosystem(purl):
            vulns = vulnerabilities.by_purl_json(purl)
            if vulns:
                for vuln in vulns:
                    for alias in vuln['aliases']:
                        if 'CVE' in alias:
                            cve_ids.add(alias)
                            dict_cve_ids_to_bom_ref[alias] = purl

    vulns = []
    if cve_ids:
        with pool.get() as conn:
            cursor = conn.cursor()
            sql = "SELECT data FROM cve WHERE data->>'id' IN (%s)" % ','.join(["'%s'" % cve_id for cve_id in cve_ids])
            cursor.execute(sql)
            results = cursor.fetchall()
            for cve in results:
                cve = cve[0]
                cve_id = cve['id']
                vuln = {
                    'bom-ref': dict_cve_ids_to_bom_ref[cve_id],
                    "id": cve_id,
                    "source": get_source(cve_id),
                    "ratings": get_ratings(cve['metrics'], min_severity),
                    "cwes": get_cwes(cve['weaknesses']),
                    "description": get_description(cve['descriptions']),
                    "published": cve['published'],
                    "updated": cve['lastModified'],
                }
                if vuln['ratings'] or min_severity is None:
                    vulns.append(vuln)
    return vulns

@purl_app.command(name="lookup")
def _lookup(target: str = typer.Argument()) -> None:
    print(f"Looking up vulnerabilities for {target}.")
    if os.path.exists(target):
        path = target
        try:
            with open(path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                if isinstance(data, dict) and 'bomFormat' in data and data['bomFormat'] == 'CycloneDX':
                    purls = extract_purls(data["components"])
                    vulns = get_vulns(purls)
                    if vulns:
                        data['vulnerabilities'] = vulns
                        output_path = path.replace('.json', '-vulns.json')
                        with open(output_path, 'w', encoding='utf-8') as file:
                            json.dump(data, file, indent=2)
                        print(f"Vulnerabilities have been written to {output_path}.")
                else:
                    print(f"The file at {target} exists but is not in CycloneDX JSON format.")

        except (JSONDecodeError, FileNotFoundError):
            pass
    else:
        vtab = Table(title=f"Vulnerabilities for purl {target}", box=box.HORIZONTALS, show_lines=True)
        vtab.add_column("id")
        vtab.add_column("aliases")
        vtab.add_column("affected")

        for vuln in vulnerabilities.by_purl(target):
            alias_tab = Table(box=None, show_header=False)
            alias_tab.add_column("alias")

            for alias in vuln.aliases:
                alias_tab.add_row(alias)

            affected_tab = Table(box=None, show_header=False)
            affected_tab.add_column("version")

            for version in vuln.affected_versions:
                affected_tab.add_row(f"version: {version}")
            for range in vuln.affected_version_ranges:
                affected_tab.add_row(f"range: {range}")

            vtab.add_row(vuln.id, alias_tab, affected_tab)

        console.print(vtab)
