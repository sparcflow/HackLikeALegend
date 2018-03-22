#!/usr/bin/python
# reads domains.txt file for URLs and IP addresses to query in the WHOIS database
import socket
import re
from subprocess import Popen, PIPE

def catch_word(pattern, output):
    match = re.search(r''+pattern+'(.+)', output)
    return match.group(1)

with open("domains.txt", "r") as ins:
    for line in ins:
        try:
            ip_address =  socket.gethostbyname(line.strip())
        except:
            print line.strip()+",,,"
            continue
        p = Popen(['whois', ip_address], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate(b"input data that is passed to subprocess' stdin")
        
        rc = p.returncode
        output = output.lower()
        if rc == 0:
            netname =  catch_word("netname:", output).strip()
            country =  catch_word("country:", output).strip()
            if "netrange" in output:
                inetnum = catch_word("netrange:", output).strip()
            elif "inetnum" in output:
                inetnum = catch_word("inetnum:", output).strip()
            print line.strip() +","+ netname +","+ inetnum +","+ country
                
            
