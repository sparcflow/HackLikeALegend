#!/usr/bin/python
# Replace the UID and SECRET variables with your own API keys from censys.io

import sys
import json
import requests

if len(sys.argv) < 2:
    print "usage " + sys.argv[0]+" <domain>";
    sys.exit();

API_URL = "https://censys.io/api/v1"
UID = "CENSYS_UID"
SECRET = "CENSYS_SECREt"
params = {"query" : sys.argv[1]}
subdomains = []
print "[+] Connecting to Censys"

res = requests.post(API_URL + "/search/certificates", json = params, auth=(UID, SECRET))

if res.status_code != 200:
    print "[-] error occurred: %s" % res.json()["error"]
    sys.exit(1)

print "[+] Parsing results"

payload = res.json()
for r in payload['results']:
    if "," in r["parsed.subject_dn"]:
         pos = r["parsed.subject_dn"].find('CN=')+3
    else:
        pos = 3
    tmp = r["parsed.subject_dn"][pos:]
    if "," in tmp:
        pos = tmp.find(",");
        tmp = tmp[:pos]
    if "." not in tmp:
        continue;
    subdomains.append(tmp)

subdomains = set(subdomains)

print "[+] "+str(len(subdomains))+" unique domains\n"
for s in subdomains:
      print  s;
