import csv
import json
import re

from pathlib import Path
from collections import defaultdict


def check_and_init_output_files(csv_mode, kenna_mode) -> str:
    current_file_path = Path(__file__).parents[1]
    csv_filename = None
    path = Path(current_file_path, 'data', 'enrichment')
    if not Path.is_dir(path):
        Path.mkdir(path, mode=0o750)

    if csv_mode:
        if kenna_mode:
            fields = ["IP", "Port", "CVE", "EPSS", "EPSS_SCORE", "CISA",
                      "CVE_Trends_tweets+retweets", "CVE_Trends_github_repos", "KENNA", "Kenna_Weekly_Chatter"]
        else:
            fields = ["IP", "Port", "CVE", "EPSS", "EPSS_SCORE", "CISA", "CVE_Trends_tweets+retweets",
                      "CVE_Trends_github_repos"]
        csv_filename = check_and_init_csv_file(fields, path)
    return csv_filename


def check_and_init_csv_file(fields, path) -> Path:
    if not Path.is_dir(path):
        Path.mkdir(path, mode=0o750)

    filename = Path(path, 'finding_enrichment_data.csv')

    with open(filename, 'w') as outfile:
        csvwriter = csv.writer(outfile)
        csvwriter.writerow(fields)
    return filename


def enrich_findings(input_file, kenna_mode, csv_mode=True):
    csv_filename = check_and_init_output_files(csv_mode, kenna_mode)
    current_file_path = Path(__file__).parents[1]
    cve_enrichment_path = Path(current_file_path, 'data', 'enrichment', 'cve_enrichment_data.json')
    with open(cve_enrichment_path) as cve_data:
        try:
            cve_data = json.load(cve_data)
        except json.decoder.JSONDecodeError:
            return "CVE Enrichment data cannot be loaded. Have you run enrich_CVE_data.py?"
    # Read input

    cve_regex_string = r'(CVE-\d{1,4}-\d+)'
    cve_regex = re.compile(cve_regex_string)
    with open(input_file) as findings:
        findings.readline()
        list_of_findings = findings.readlines()

    enriched_findings_dict = lambda: defaultdict(enriched_findings_dict)
    enriched_findings = enriched_findings_dict()

    for finding in list_of_findings:

        cve_info = re.findall(cve_regex, finding)
        line_info = finding.split(',')
        ip_addr = line_info[0]
        port = int(line_info[1])

        for cve in cve_info:
            try:
                enriched_findings[ip_addr][port][cve] = cve_data[cve]
            except KeyError:
                enriched_findings[ip_addr][port][cve] = cve_data['not_in_any']

    finding_enrichment_path = Path(current_file_path, 'data', 'enrichment', 'finding_enrichment_data.json')
    try:
        with open(finding_enrichment_path) as old_findings_file:
            try:
                old_findings = json.load(old_findings_file)
            except json.decoder.JSONDecodeError:
                old_findings = {}
    except:
        old_findings = {}
    updated_findings = old_findings | enriched_findings
    with open(finding_enrichment_path, 'w') as out_json:
        json.dump(updated_findings, out_json)

    if csv_mode:
        write_csv_output(csv_filename, updated_findings, kenna_mode)
    return "SenPy has successfully enriched your findings."


def write_csv_output(csv_file, findings, kenna_mode) -> None:
    with open(csv_file, 'a') as csv_handle:
        csvwriter = csv.writer(csv_handle)
        for ip, service in findings.items():
            for port, cve_title in service.items():
                for cve_data, enrichment in cve_title.items():
                    if kenna_mode:
                        fields = [ip, port, cve_data, enrichment['EPSS'], enrichment['EPSS_score'], enrichment['CISA'],
                                  enrichment['CVE_Trends_tweets+retweets'], enrichment['CVE_Trends_github_repos'],
                                  enrichment['Kenna'], enrichment['Kenna_weekly_chatter']]

                    else:
                        fields = [ip, port, cve_data, enrichment['EPSS'], enrichment['EPSS_score'], enrichment['CISA'],
                                  enrichment['CVE_Trends_tweets+retweets'], enrichment['CVE_Trends_github_repos']]
                    csvwriter.writerow(fields)


if __name__ == "__main__":
    print("Use SenPy.py")
