import sys, json, requests, logging, os
import censys.certificates

API_URL = "https://censys.io/api/v1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def close_to_domain(candidate, target_domain, domain_array):
    if any(x in candidate for x in domain_array):
        return True
    return False


def show_censys_data(domain, uid, secret):
    logger.info("Looking up {} on censys".format(domain))
    domains = set()
    domain_array = domain.split(".")
    domain_array.pop()

    certificates = censys.certificates.CensysCertificates(uid, secret)
    fields = ["parsed.names"]

    for c in certificates.search("parsed.names: %s" % domain, fields=fields):
        for d in c["parsed.names"]:
            if close_to_domain(d, domain, domain_array):
                domains.add(d)

    logger.info("Found {} unique domains".format(len(domains)))
    for d in domains:
        print(d)


def check_api_keys():
    if os.environ.get("CENSYS_ID") is None or os.environ.get("CENSYS_SECRET") is None:
        logger.warning("Missing CENSYS_ID or CENSYS_SECRET env var")
        sys.exit(-1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage {} <domain>".format(sys.argv[0]))
        sys.exit(-1)
    check_api_keys()
    uid = os.environ.get("CENSYS_ID")
    secret = os.environ.get("CENSYS_SECRET")

    show_censys_data(sys.argv[1], uid, secret)
