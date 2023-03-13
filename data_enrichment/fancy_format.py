import csv
import json
import re
from pathlib import Path


current_file_path = Path(__file__).parents[1]
enrich_out_path = Path(current_file_path, 'data', 'enrichment')
enriched_cve_data = Path(enrich_out_path, 'cve_enrichment_data.json')


def get_enrichment_data(enrichment_file_loc) -> json:
    f = open(enrichment_file_loc, 'r')
    jason = json.load(f)
    return jason


def fancy_format(filename="") -> str:
    kenna_mode = False
    cve_regex_string = r'(CVE-\d{1,4}-\d+)'
    cve_regex = re.compile(cve_regex_string)

    with open(filename, 'r') as input_file:
        csv_file = csv.reader(input_file, dialect='excel', delimiter=',', quotechar='"')

        headers = next(csv_file)
        headers = list(map(str.upper, headers))

        cve_json = get_enrichment_data(enriched_cve_data)

        fields = ["CVE", "EPSS", "EPSS_SCORE", "CISA", "CVE_Trends_tweets+retweets", "CVE_Trends_github_repos"]
        if 'Kenna' in cve_json['not_in_any']:
            kenna_mode = True
        kenna_fields = ['Kenna', 'Kenna_weekly_chatter_trend', 'Kenna_daily_chatter_trend',
                        'Kenna_monthly_chatter_trend', 'Kenna_weekly_chatter', 'Kenna_daily_chatter',
                        'Kenna_monthly_chatter']

        headers.extend(fields)
        if kenna_mode:
            headers.extend(kenna_fields)
        out_path = Path(current_file_path, 'data', 'enrichment')
        stripped_name = Path(filename).stem
        outfile_name = f"{stripped_name}_enriched_fancy.csv"
        outfile = Path(out_path, outfile_name)

        out = open(outfile, 'w')
        out_csv = csv.writer(out, dialect='excel', delimiter=',', quotechar='"')
        out_csv.writerow(headers)
        for row in csv_file:
            str_row = ' '.join(str(col) for col in row)
            cve_info = re.findall(cve_regex, str_row)
            if len(cve_info) == 0:
                out_csv.writerow(row)
            else:
                cve_info = set(cve_info)
                for cve in cve_info:
                    try:
                        cve_data = [cve, cve_json[cve]['EPSS'], cve_json[cve]['EPSS_score'], cve_json[cve]['CISA'],
                                    cve_json[cve]['CVE_Trends_tweets+retweets'],
                                    cve_json[cve]['CVE_Trends_github_repos']]
                        if kenna_mode:
                            kenna_data = [cve_json[cve]['Kenna'], cve_json[cve]['Kenna_weekly_chatter_trend'],
                                          cve_json[cve]['Kenna_daily_chatter_trend'],
                                          cve_json[cve]['Kenna_monthly_chatter_trend'],
                                          cve_json[cve]['Kenna_weekly_chatter'],
                                          cve_json[cve]['Kenna_daily_chatter'], cve_json[cve]['Kenna_monthly_chatter']]
                            cve_data.extend(kenna_data)

                    except KeyError:
                        cve_data = [cve, '', '', '',
                                    '', '',
                                    '', '',
                                    '',
                                    '', '',
                                    '', '']
                        outrow = row + cve_data
                        out_csv.writerow(outrow)
        out.close()
        return f"Output fancified as {outfile}"


if __name__ == "__main__":
    fancy_format()
