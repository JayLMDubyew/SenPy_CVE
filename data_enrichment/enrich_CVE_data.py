from collections import defaultdict
import requests
import json
import os
from pathlib import Path
import csv
import datetime


def do_we_need_an_update(aggressive_update=False, csv_mode=False, kenna_mode=False) -> bool:
    outfile = check_and_init_output_file(csv_mode, kenna_mode)
    if aggressive_update or not os.path.isfile(outfile):
        return True
    else:
        threshold = datetime.datetime.now() - datetime.timedelta(hours=24)
        if threshold > datetime.datetime.fromtimestamp(os.path.getmtime(outfile)):
            return True
    return False


def check_and_init_output_file(csv_mode=False, kenna_mode=False) -> Path:
    current_file_path = Path(__file__).parents[1]
    path = Path(current_file_path, 'data', 'enrichment')
    if not Path.is_dir(path):
        Path.mkdir(path, mode=0o750)

    filename = Path(path, 'cve_enrichment_data')

    fields = ["CVE", "EPSS", "EPSS_SCORE", "CISA", "CVE_Trends_tweets+retweets",
              "CVE_Trends_github_repos"]
    if kenna_mode:
        fields.extend(
            ['Kenna', 'Kenna_weekly_chatter_trend', 'Kenna_daily_chatter_trend', 'Kenna_monthly_chatter_trend',
             'Kenna_daily_chatter', 'Kenna_weekly_chatter', 'Kenna_monthly_chatter'])

    check_and_init_csv_file(fields, filename)

    return filename.with_suffix('.json')


def check_and_init_csv_file(fields, path) -> None:
    filename = path.with_suffix('.csv')

    with open(filename, 'w') as outfile:
        csvwriter = csv.writer(outfile)
        csvwriter.writerow(fields)


def get_data(kenna_api_key="", kenna_base_url="", aggressive_update=False, EPSS_score=0.50, cvetrends_span="7days",
             csv_mode=False, kenna_mode=False) -> str:
    if do_we_need_an_update(aggressive_update, csv_mode, kenna_mode):
        vulners = defaultdict(defaultdict)

        epss_base_url = f"https://api.first.org/data/v1/epss?epss-gt={EPSS_score}"
        cvetrends_url = f"https://cvetrends.com/api/cves/{cvetrends_span}"
        cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        epss_info = requests.get(epss_base_url)
        epss_data = epss_info.json()['data']
        for vuln in epss_data:
            vulners[vuln["cve"]]["EPSS"] = 1
            vulners[vuln["cve"]]["EPSS_score"] = vuln["epss"]
            continue

        cvetrends_info = requests.get(cvetrends_url)
        cvetrends_data = cvetrends_info.json()['data']
        for vuln in cvetrends_data:
            vulners[vuln["cve"]]["CVE_Trends_tweets+retweets"] = vuln['num_tweets_and_retweets']
            vulners[vuln["cve"]]["CVE_Trends_github_repos"] = []
            if vuln['github_repos']:
                for repo in vuln['github_repos']:
                    vulners[vuln["cve"]]["CVE_Trends_github_repos"].append(repo["url"])

        cisa_kev_info = requests.get(cisa_kev_url)
        cisa_kev_data = cisa_kev_info.json()['vulnerabilities']
        for vuln in cisa_kev_data:
            vulners[vuln["cveID"]]['CISA'] = 1

        if kenna_mode:
            url = f"{kenna_base_url}/vulnerability_definitions/cve_identifiers?minimal_risk_score=67" \
                  f"&active_internet_breach=true&easily_exploitable=true "
            headers = {
                "accept": "application/json",
                "X-Risk-Token": kenna_api_key
            }
            kenna_info = requests.get(url, headers=headers)
            kenna_data = kenna_info.json()['cve_identifiers']
            for vuln in kenna_data:
                vulners[vuln]['Kenna'] = 1

            kenna_chatter_url = f"{kenna_base_url}/vulnerability_definitions/trends?trend=chatter&sort_by=month"
            kenna_chatter_info = requests.get(kenna_chatter_url, headers=headers)
            kenna_chatter_data = kenna_chatter_info.json()["trends"]
            for chatter in kenna_chatter_data:
                vuln = chatter['cve_identifier']
                vulners[vuln]['Kenna_weekly_chatter_trend'] = chatter['percentage_change_per_week']
                vulners[vuln]['Kenna_daily_chatter_trend'] = chatter['percentage_change_per_day']
                vulners[vuln]['Kenna_monthly_chatter_trend'] = chatter['percentage_change_per_month']
                vulners[vuln]['Kenna_daily_chatter'] = chatter['last_day']
                vulners[vuln]['Kenna_weekly_chatter'] = chatter['last_week']
                vulners[vuln]['Kenna_monthly_chatter'] = chatter['last_month']

        vulners['not_in_any'] = {}
        filename_base = check_and_init_output_file(kenna_mode, csv_mode)
        json_filename = filename_base.with_suffix('.json')
        csv_filename = filename_base.with_suffix('.csv')

        for vuln in vulners:
            numerical_fields = ['CISA', 'EPSS', 'EPSS_score', 'CVE_Trends_tweets+retweets', ]
            kenna_fields = ['Kenna', 'Kenna_weekly_chatter_trend', 'Kenna_daily_chatter_trend',
                            'Kenna_monthly_chatter_trend', 'Kenna_daily_chatter', 'Kenna_weekly_chatter',
                            'Kenna_monthly_chatter']
            if kenna_mode:
                numerical_fields.extend(kenna_fields)
            for field in numerical_fields:
                vulners[vuln].setdefault(field, 0)
            non_numerical_fields = ['CVE_Trends_github_repos']
            for field in non_numerical_fields:
                vulners[vuln].setdefault(field, [])
            if csv_mode:
                with open(csv_filename, 'a') as csv_output:
                    csv_write = csv.writer(csv_output)
                    out_line = [vuln, vulners[vuln]['EPSS'], vulners[vuln]['EPSS_score'], vulners[vuln]['CISA'],
                                vulners[vuln]['CVE_Trends_tweets+retweets'], vulners[vuln]['CVE_Trends_github_repos']]
                    if kenna_mode:
                        kenna_out = [vulners[vuln]['Kenna'], vulners[vuln]['Kenna_weekly_chatter_trend'],
                                     [vulners[vuln]['Kenna_daily_chatter_trend'],
                                      vulners[vuln]['Kenna_monthly_chatter_trend'],
                                      vulners[vuln]['Kenna_daily_chatter'], vulners[vuln]['Kenna_weekly_chatter'],
                                      vulners[vuln]['Kenna_monthly_chatter']]]
                        out_line.extend(kenna_out)

                    csv_write.writerow(out_line)

        with open(json_filename, 'w') as data:
            json.dump(vulners, data)
        return "Successfully updated CVE Metadata."
    return "CVE Metadata not updated. Data is less than 24 hours old. Set aggressive_enrichment in config.ini if you " \
           "want to force enrichment. "


if __name__ == "__main__":
    print(get_data())
