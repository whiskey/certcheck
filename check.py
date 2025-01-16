import ssl
import socket
import OpenSSL
import concurrent.futures
from collections import defaultdict
from typing import List, Dict, Tuple
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
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
                    x509 = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert_binary
                    )
                    
                    # Get all SANs
                    sans = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if ext.get_short_name() == b'subjectAltName':
                            sans_raw = str(ext)
                            # Parse SANs string and extract domain names
                            sans = [san.split(':')[1] for san in sans_raw.split(',')
                                  if 'DNS:' in san]
                    
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
            future_to_domain = {
                executor.submit(self.get_certificate, domain): domain
                for domain in domains
            }
            
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

        return dict(sorted(
            self.results.items(),
            key=lambda x: x[1],
            reverse=True
        ))

def main():
    # Top 50+ Domains in Germany plus some US pages
    domains = [
        # Initial set
        "google.com", "amazon.com", "facebook.com", "microsoft.com",
        "apple.com", "netflix.com", "twitter.com", "linkedin.com",
        "bmwgroup.com", "deutsche-bank.de", "staticline.de",
        # Germany top 50
        "google.de",
        "google.com",
        "youtube.com",
        "amazon.de",
        "ebay.de",
        "wikipedia.org",
        "facebook.com",
        "ebay-kleinanzeigen.de",
        "reddit.com",
        "gmx.net",
        "t-online.de",
        "instagram.com",
        "netflix.com",
        "xhamster.com",
        "web.de",
        "pornhub.com",
        "twitter.com", "x.com",
        "microsoft.com",
        "yahoo.com",
        "bild.de",
        "otto.de",
        "whatsapp.com",
        "twitch.tv",
        "paypal.com",
        "live.com",
        "tiktok.com",
        "linkedin.com",
        "fandom.com",
        "amazon.com",
        "chaturbate.com",
        "focus.de",
        "deutsche-bank.de",
        "sparkasse.de",
        "chip.de",
        "zeit.de",
        "office.com",
        "spiegel.de",
        "wetteronline.de",
        "wetter.com",
        "microsoft365.com",
        "idealo.de",
        "xnxx.com",
        "bing.com",
        "commerzbank.de",
        "booking.com",
        "dhl.de",
        "dkb.de",
        "comdirect.de",
        "ing.de",
        "mediamarkt.de"
    ]
    # Add more domains as needed
    
    analyzer = CertificateAnalyzer()
    logger.info("Starting certificate analysis...")
    
    results = analyzer.analyze_domains(domains)
    
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
    main()

