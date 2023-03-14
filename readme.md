# You noticed SenPy!
Do you have too many vulnerabilities and CVSS is absolutely useless in determining how you should prioritize them? Do you like extra fields to use to yell at people?
Then SenPy might help you!


## What does SenPy do?
CVSS is great for describing the characteristics of a vulnerability. However, it's a relatively static set of characteristics.
If you're working with ornery folks who are sick of you knocking down their door to get vulnerabilities fixed, you know how it goes.

SenPy is not reinventing the wheel. There's people out there who are smarter than I am, with more resources, mature processes, and man-hours to commit to creating a mature and useful set of data. 
SenPy takes this data, and then applies it to findings.

# What Senpy Does
### CVE Data Enrichment 
- Takes file input and performs data enrichment based for vulnerabilities based off of four feeds:
  - CISA Known Exploited Vulnerabilities (KEV)
    - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - EPSS Probability Score >=.10 (default)
    - https://www.first.org/epss/
  - CVE Trends over the last 7 days
    - https://cvetrends.com
    - Note: CVEtrends data changes frequently, so information such as github repo data may not persist between updates.
  - Kenna (Optional. Requires Kenna VI+ subscription.) 
    - https://www.kennasecurity.com
    - Kenna chatter metrics for applicable vulns
    - Items marked as meeting all three of the criteria below:
      - actively breached
      - easily exploitable
      - Kenna Score is >= 34 (Amber Meter)
- Data enrichment data will, by default, only update if it has been more than 24 hours since it was last refreshed.
  - In order to override this, enter the following under the "general" stanza in config.ini:
    - _aggressive_enrichment = True_

### Vulnerability Finding data enrichment 
- Senpy can take enrichment 
### Usage
SenPy.py [--i CSV_data_file]
- CSV data file is optional if you want SenPy to perform enrichment against findings.


##### Don't complain, you're getting this for free.


#### Config.ini

Don't put double quotes around string values.

[general]
uwu - Boolean. sets uwu mode

serious - Boolean. sets serious mode. Will override April fool's UwU mode
aggressive_enrichment = Boolean. Force CVE enrichment data to pull each time SenPy is run instead of every 24 hours.

EPSS_score = Float. Minimum EPSS score to pull.

cvetrends_span = String. CVE Trends Timespan to use. Can be 24hrs or 7days.

cve_csv_output = Boolean. Output Enriched CVE data as CSV output. JSON output will also be done.

finding_csv_output = Boolean. Output Enriched Finding data as CSV output. JSON output will also be done.
  - Output will only contain Host, Port, and CVE data. If you want more information, such as info from your scanner, use fancy_csv_output
  - Finding data must have the first column set to ip, the second to the port that the finding was found on, or else SenPy will flip out.


fancy_csv_output = Boolean. For use with scanner output if you want to append finding data to fields from scanner output such as Qualys or Tenable.
  - Column order does not matter, however, if you have multiple CVEs on one line due to your scanning using a single plugin for multiple CVES (I'm looking at you, Tenable), then output will one line per CVE. This is intended behavior, but it may cause duplicate lines depending on how you feed data into SenPy.


[kenna_config]

url = String. Your Kenna base URL here.

api_key = String. Your Kenna API Keys here. 


### Output
- All output is stored in the data/data_enrichment directory. The names are self-explanatory.
- Output is in JSON format by default so you can slap it into an API or something. 
  - CVE output can be done for by editing config.ini

# UwU Mode
- If you want the respect of your peers, I highly suggest that you *don’t* use UwU mode. You have been warned.
- I mainly made this portion because it's almost April.


# My incredibly biased view of how helpful SenPy is.
### Without SenPy
>You: "Hi. You have vulnerabilities."
>
>_2 days later_
>
>You: "Hello, I know you're ornery, but I know you can type. I've seen the mean messages you've deleted from our group chat."
>
>_*crickets*_
>
>_2 weeks later_
>
>You: "Ok, I need you to answer me."
> 
>Ornery Operator Who Doesn't Care (OOWDC): "...and? You pinged me last month because I'm running a vulnerable version of [software name here] from 201X." 
>
>You: "Yep. We also found more stuff. The CVSS string for this one is: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:X/RC:X/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H`. You should fix it."
>
>OOWDC: "...aaaaaaand??? I don't read CVSS, _brohan_.  I have more important things to care about. Buzz off. Policy ain't gonna do anything if you can't show me any actual potential impact"
>
>You: "...ok then. Let me go grab a bunch of evidence that this is a real problem."
>
>_3 hours later_
>
> You: "Ok here's your evidence."
>
>**Back and forth ensues for a month. You cite policy, OOWDC cites business needs. OOWDC's boss gets an exception because you didn't have enough proof. [your corp name here] inevitably gets popped by this embarrassingly low hanging fruit.** 

### With SenPy
> "You. Hi you have vulnerabilities. SenPy noticed (through its data feeds) that there are GitHub repos with exploits for this vulnerability, FIRST's EPSS data has marked this likely to be exploited, and the U.S. Government says that it's being exploited by threat actors."
> 
>_*crickets*_
> 
> You: "Ok, dude. I gave you your proof that this a problem. Fix it."
> 
> OOWDC:"Yeah, maybe in a sprint next quarter, mmkay? I'm on vacation in Hawaii. Don't bother me."
> 
> You: "...Hold on. Did you see this message before you went to Hawaii?"
> 
> OOWDC: "Yes, but I was mentally in Hawaii."
> 
> You: "Yeah, no. Fix it now."
> 
> OOWDC: "...but _HAWAII_"
> 
> You: "Yo, _OOWDC's boss_, is this your stance on cybersecurity issues that have proof that this is a Real Problem™?"
> 
> OOWDC'S Boss: "...yo what the heck??? Fix this, OOWDC."
> 
> _OOWDC passive aggressively and drunkenly narrates their mitigation of the vulnerability, all while drinking a blue Hawaii. You fall into the datacenter floor a month later._
