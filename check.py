import argparse
import concurrent.futures
import logging
import socket
import ssl
from collections import defaultdict
from typing import List, Dict, Tuple

import OpenSSL

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CertificateAnalyzer:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results: Dict[str, int] = defaultdict(int)
        self.errors: List[str] = []

    def get_certificate(self, domain: str) -> Tuple[str, List[str]]:
        """
        Retrieve SSL certificate for a given domain and extract SANs.
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)

                    # Get all SANs
                    sans = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if ext.get_short_name() == b'subjectAltName':
                            sans_raw = str(ext)
                            # Parse SANs string and extract domain names
                            sans = [san.split(':')[1] for san in sans_raw.split(',') if 'DNS:' in san]

                    return domain, sans

        except Exception as e:
            logger.error(f"Error processing {domain}: {str(e)}")
            self.errors.append(f"{domain}: {str(e)}")
            return domain, []

    def analyze_domains(self, domains: List[str], max_workers: int = 10) -> Dict[str, int]:
        """
        Analyze multiple domains concurrently and count their SANs.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {executor.submit(self.get_certificate, domain): domain for domain in domains}

            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    _, sans = future.result()
                    # Subtract 1 to exclude the main domain
                    additional_domains = len(sans) - 1 if sans else 0
                    if additional_domains > 0:
                        self.results[domain] = additional_domains
                except Exception as e:
                    logger.error(f"Error processing future for {domain}: {str(e)}")

        return dict(sorted(self.results.items(), key=lambda x: x[1], reverse=True))


def main(args):
    domains = []
    if args.file is not None:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.append(line)
            logger.info(f"Loaded {len(domains)} domains from {args.file}")
        except Exception as e:
            logger.error(f"Error loading file {args.file}: {str(e)}")
    else:
        default_domains = [# Global Tech
            "google.com", "amazon.com", "facebook.com", "microsoft.com", "apple.com", "netflix.com", "twitter.com",
            "linkedin.com", "aliexpress.com", "yahoo.com", "ebay.com", "pinterest.com", # German Tech & Media
            "google.de", "youtube.com", "amazon.de", "ebay.de", "wikipedia.org", "ebay-kleinanzeigen.de", "reddit.com",
            "gmx.net", "t-online.de", "instagram.com", "web.de", "bild.de", "otto.de", "twitch.tv", "focus.de",
            "chip.de", "zeit.de", "spiegel.de", "wetteronline.de", "wetter.com", "idealo.de", "mediamarkt.de",
            # German Banks & Finance
            "bmwgroup.com", "deutsche-bank.de", "sparkasse.de", "hypovereinsbank.de", "commerzbank.de", "dkb.de",
            "comdirect.de", "ing.de", # Services & Social
            "whatsapp.com", "paypal.com", "live.com", "tiktok.com", "fandom.com", "office.com", "microsoft365.com",
            "bing.com", "booking.com", "dhl.de", # Adult Content
            "xhamster.com", "pornhub.com", "chaturbate.com", "xnxx.com", # Special Sites
            "manatoki319.net", "newtoki317.com"]
        domains = default_domains

    analyzer = CertificateAnalyzer(timeout=args.timeout)
    logger.info(f"Starting certificate analysis with {args.workers} workers...")

    results = analyzer.analyze_domains(domains, max_workers=args.workers)

    # Print top 100 results
    print("\nTop domains by number of additional domain names:")
    print("-" * 60)
    print(f"{'Domain':<30} | {'Additional Domains':>20}")
    print("-" * 60)

    for domain, count in list(results.items())[:100]:
        print(f"{domain:<30} | {count:>20}")

    # Print errors if any
    if analyzer.errors:
        print("\nErrors encountered:")
        for error in analyzer.errors:
            print(f"- {error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze SSL certificates for domains')
    parser.add_argument('-f', '--file', help='File containing domains (one per line)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout for each connection in seconds')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers')
    args = parser.parse_args()
    # Load domains from file if provided, otherwise use default list
    main(args)
