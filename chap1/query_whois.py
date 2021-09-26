import socket, sys, re, logging
from subprocess import Popen, PIPE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def usage():
    if len(sys.argv) < 2:
        print("usage query_whois.py <domain_file>")
        print("\t<domain_file> contains a domain per line")
        sys.exit(-1)

def catch_word(pattern, output):
    match = re.search('%s(.+)' % pattern, output)
    return match.group(1)

def get_ip_from_domain(domain_name):
    try:
        return socket.gethostbyname(domain_name)
    except Exception as e:
        logger.warn("Could not resolve %s - %s" % (domain_name, e))
        return None

def parse_whoise(ip_address):
    netname, inetnum, country  = "N/A", "N/A", "N/A"
    p = Popen(['whois', ip_address], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()

    rc = p.returncode
    output = output.lower().decode()
    if rc == 0:
        netname =  catch_word("netname:", output).strip()
        country =  catch_word("country:", output).strip()
        if "netrange" in output:
            inetnum = catch_word("netrange:", output).strip()
        elif "inetnum" in output:
            inetnum = catch_word("inetnum:", output).strip()
    return netname, inetnum, country

def run():
    print("domain,netname,ip range,country")
    with open(sys.argv[1], "r") as ins:
        for line in ins:
            domain_name = line.strip()
            ip_address = get_ip_from_domain(domain_name)
            if ip_address is None:
                print("{},,,".format(domain_name))
                continue
            netname, inetnum, country = parse_whoise(ip_address)
            print("{},{},{},{}".format(domain_name, netname, inetnum, country))


if __name__ == "__main__":
    usage()
    run()