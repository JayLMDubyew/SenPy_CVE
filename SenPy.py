import argparse
import datetime
from configparser import ConfigParser
import data_enrichment.enrich_CVE_data as cve_enrich
import data_enrichment.enrich_finding_data as finding_enrich
import uwu
import data_enrichment.fancy_format as fancy
from pathlib import Path

config_info = ConfigParser()
init = 'config.ini'

config_info.read(init)

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-i', '--input_file', default='', help='Finding data to enrich')
args = arg_parser.parse_args()
csv_to_enrich = args.input_file

serious_mode = config_info.getboolean('general', 'serious')
uwu_mode = config_info.getboolean('general', 'uwu')
kenna_url = config_info.get('kenna_config', 'url')
kenna_api_key = config_info.get('kenna_config', 'api_key')
uwu_mode = config_info.getboolean('general', 'uwu')
aggressive_enrichment = config_info.getboolean('general', 'aggressive_enrichment')
EPSS_score = config_info.getfloat('general', 'EPSS_score')
cvetrends_span = config_info.get('general', 'cvetrends_span')
cve_csv_output = config_info.getboolean('general', 'cve_csv_output')
finding_csv_output = config_info.getboolean('general', 'finding_csv_output')
fancy_csv_output = config_info.getboolean('general', 'fancy_csv_output')

if not serious_mode:
    today = datetime.date.today()
    april_fools_day = datetime.date(today.year, 4, 1)
    if today == april_fools_day:
        uwu_mode = True

if kenna_url and kenna_api_key:
    kenna_mode = True
else:
    kenna_mode = False

kenna_status = f"Kenna mode is {kenna_mode}"
getting_cve = "Checking CVE data and updating if needed... this may take a moment."
finding_data_en = f"Enriching findings from {csv_to_enrich}. If there's an error, refer to formatting guidance in " \
                  f"readme.md "
fancying = f"Fancifying {csv_to_enrich}."

print(finding_data_en)

if uwu_mode:
    uwu.hewwo()
    print(uwu.uwuIt(kenna_status) + f"{uwu.uwuIt('yay!!!!')}")
    print((uwu.uwuIt(getting_cve)))
    print(uwu.uwuIt(
        cve_enrich.get_data(kenna_api_key, kenna_url, aggressive_enrichment, EPSS_score, cvetrends_span, cve_csv_output,
                            kenna_mode)))
    current_file_path = Path(__file__).parents[0]

    if finding_csv_output:
        print(uwu.uwuIt(finding_data_en))
        print(uwu.uwuIt(finding_enrich.enrich_findings(Path(csv_to_enrich), kenna_mode, finding_csv_output)))
    if fancy_csv_output:
        print(uwu.uwuIt("what's this?????? faaaaaancy mode???!!!?!?!?!?!!?!?!?!?!"))
        print(uwu.uwuIt(fancying))
        print(uwu.uwuIt(fancy.fancy_format(Path(csv_to_enrich))))

else:
    print(kenna_status)
    print(getting_cve)
    print(
        cve_enrich.get_data(kenna_api_key, kenna_url, aggressive_enrichment, EPSS_score, cvetrends_span, cve_csv_output,
                            kenna_mode))
    current_file_path = Path(__file__).parents[0]

    if finding_csv_output:
        print(finding_data_en)
        print(finding_enrich.enrich_findings(Path(csv_to_enrich), kenna_mode, finding_csv_output))
    if fancy_csv_output:
        print(fancying)
        print(fancy.fancy_format(Path(csv_to_enrich)))
