#!/usr/bin/env python3
"""
sslq - SSL/TLS Post-Quantum Cryptography Scanner
Analyzes websites for Post-Quantum Cryptography support in TLS/SSL connections
"""

import ssl
import socket
import argparse
import sys
import subprocess
import shutil
import re
from urllib.parse import urlparse
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("[!] Warning: cryptography library not installed. Install with: pip install cryptography")


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class PQCDetector:
    """Detects Post-Quantum Cryptography in TLS/SSL connections"""

    # Post-Quantum Cryptography algorithms and identifiers
    PQC_ALGORITHMS = {
        # NIST PQC selected algorithms
        'KYBER': ['kyber', 'mlkem', 'ML-KEM'],
        'DILITHIUM': ['dilithium', 'mldsa', 'ML-DSA'],
        'SPHINCS': ['sphincs', 'sphincsplus', 'slhdsa', 'SLH-DSA'],

        # NIST finalists and alternates
        'FALCON': ['falcon'],
        'NTRU': ['ntru', 'ntruhrss', 'ntrulprime'],
        'SABER': ['saber'],
        'BIKE': ['bike'],
        'HQC': ['hqc'],
        'FRODO': ['frodo', 'frodokem'],

        # Hybrid algorithms
        'HYBRID': ['hybrid', 'x25519_kyber', 'x25519kyber', 'x25519mlkem', 'p256_kyber', 'p256kyber', 'secp256r1_kyber']
    }

    # Classical algorithms (pre-quantum)
    CLASSICAL_ALGORITHMS = {
        'RSA': ['rsa'],
        'ECDSA': ['ecdsa', 'secp256r1', 'secp384r1', 'secp521r1', 'prime256v1'],
        'DSA': ['dsa'],
        'DH': ['dh', 'dhe'],
        'ECDH': ['ecdh', 'ecdhe']
    }

    def __init__(self, timeout: int = 10, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.openssl_available = shutil.which('openssl') is not None

        if self.verbose and self.openssl_available:
            print(f"[*] OpenSSL detected: Enhanced PQC detection enabled")

    def parse_url(self, url: str) -> tuple:
        """Parse URL and extract hostname and port"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        return hostname, port

    def detect_pqc_in_text(self, text: str) -> Dict[str, List[str]]:
        """Detect PQC algorithms in text (case-insensitive)"""
        text_lower = text.lower()
        found_pqc = {}

        for algo_name, keywords in self.PQC_ALGORITHMS.items():
            matches = [kw for kw in keywords if kw.lower() in text_lower]
            if matches:
                found_pqc[algo_name] = matches

        return found_pqc

    def get_openssl_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """Use OpenSSL to get detailed TLS/PQC information"""
        result = {
            'success': False,
            'negotiated_group': None,
            'pqc_detected': False,
            'error': None
        }

        if not self.openssl_available:
            return result

        try:
            cmd = [
                'openssl', 's_client',
                '-connect', f'{hostname}:{port}',
                '-tls1_3',
                '-brief'
            ]

            proc = subprocess.run(
                cmd,
                input='\n',
                capture_output=True,
                timeout=self.timeout,
                text=True
            )

            output = proc.stdout + proc.stderr

            # Extract negotiated group
            group_match = re.search(r'Negotiated TLS1\.3 group:\s*(\S+)', output, re.IGNORECASE)
            if group_match:
                result['negotiated_group'] = group_match.group(1)
                result['success'] = True

                # Check if group contains PQC
                pqc_in_group = self.detect_pqc_in_text(result['negotiated_group'])
                if pqc_in_group:
                    result['pqc_detected'] = True
                    result['pqc_algorithms'] = pqc_in_group

        except subprocess.TimeoutExpired:
            result['error'] = f"OpenSSL timeout after {self.timeout}s"
        except Exception as e:
            result['error'] = f"OpenSSL error: {str(e)}"

        return result

    def analyze_cipher_suite(self, cipher_name: str) -> Dict[str, Any]:
        """Analyze cipher suite for PQC and classical algorithms"""
        result = {
            'name': cipher_name,
            'pqc_detected': False,
            'pqc_algorithms': {},
            'classical_algorithms': {},
            'is_hybrid': False
        }

        # Check for PQC algorithms
        pqc_found = self.detect_pqc_in_text(cipher_name)
        if pqc_found:
            result['pqc_detected'] = True
            result['pqc_algorithms'] = pqc_found
            if 'HYBRID' in pqc_found:
                result['is_hybrid'] = True

        # Check for classical algorithms
        cipher_lower = cipher_name.lower()
        for algo_name, keywords in self.CLASSICAL_ALGORITHMS.items():
            if any(kw in cipher_lower for kw in keywords):
                result['classical_algorithms'][algo_name] = True

        return result

    def get_ssl_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """Connect to server and retrieve SSL/TLS information"""
        result = {
            'hostname': hostname,
            'port': port,
            'success': False,
            'error': None,
            'ssl_version': None,
            'cipher_suite': None,
            'cipher_analysis': None,
            'certificate': None,
            'pqc_detected': False,
            'pqc_summary': []
        }

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Try to use the most recent TLS version
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            # Connect to server
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get SSL/TLS version
                    result['ssl_version'] = ssock.version()

                    # Get cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        result['cipher_suite'] = {
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        }

                        # Analyze cipher suite
                        result['cipher_analysis'] = self.analyze_cipher_suite(cipher[0])
                        if result['cipher_analysis']['pqc_detected']:
                            result['pqc_detected'] = True
                            result['pqc_summary'].append(f"PQC in cipher: {cipher[0]}")

                    # Get certificate
                    if CRYPTOGRAPHY_AVAILABLE:
                        cert_der = ssock.getpeercert(binary_form=True)
                        if cert_der:
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())
                            result['certificate'] = self.parse_certificate(cert)

                            # Check certificate signature algorithm for PQC
                            sig_algo = str(cert.signature_algorithm_oid._name)
                            pqc_in_sig = self.detect_pqc_in_text(sig_algo)
                            if pqc_in_sig:
                                result['pqc_detected'] = True
                                result['pqc_summary'].append(f"PQC in signature: {sig_algo}")

                    result['success'] = True

        except socket.gaierror as e:
            result['error'] = f"DNS resolution failed: {e}"
        except socket.timeout:
            result['error'] = f"Connection timeout after {self.timeout}s"
        except ssl.SSLError as e:
            result['error'] = f"SSL error: {e}"
        except ConnectionRefusedError:
            result['error'] = "Connection refused"
        except Exception as e:
            result['error'] = f"Unexpected error: {type(e).__name__}: {e}"

        # Use OpenSSL for enhanced PQC detection (TLS 1.3 groups)
        if self.openssl_available and result['success']:
            openssl_info = self.get_openssl_info(hostname, port)
            result['openssl_info'] = openssl_info

            if openssl_info.get('pqc_detected'):
                result['pqc_detected'] = True
                group_name = openssl_info.get('negotiated_group', 'Unknown')
                result['pqc_summary'].append(f"PQC in key exchange: {group_name}")

        return result

    def parse_certificate(self, cert: Any) -> Dict[str, Any]:
        """Parse X.509 certificate and extract relevant information"""
        cert_info = {
            'subject': {},
            'issuer': {},
            'version': cert.version.name,
            'serial_number': cert.serial_number,
            'not_valid_before': cert.not_valid_before_utc.isoformat(),
            'not_valid_after': cert.not_valid_after_utc.isoformat(),
            'signature_algorithm': str(cert.signature_algorithm_oid._name),
            'public_key_algorithm': None,
            'public_key_size': None,
            'pqc_detected': False
        }

        # Parse subject
        for attr in cert.subject:
            cert_info['subject'][attr.oid._name] = attr.value

        # Parse issuer
        for attr in cert.issuer:
            cert_info['issuer'][attr.oid._name] = attr.value

        # Parse public key
        public_key = cert.public_key()
        key_type = type(public_key).__name__
        cert_info['public_key_algorithm'] = key_type

        try:
            if hasattr(public_key, 'key_size'):
                cert_info['public_key_size'] = public_key.key_size
        except:
            pass

        # Check for PQC in certificate
        cert_text = f"{cert_info['signature_algorithm']} {key_type}"
        pqc_found = self.detect_pqc_in_text(cert_text)
        if pqc_found:
            cert_info['pqc_detected'] = True
            cert_info['pqc_algorithms'] = pqc_found

        return cert_info

    def format_output(self, result: Dict[str, Any]) -> str:
        """Format result as sslyze-style output"""
        output = []

        # Header
        output.append(f"\n{Colors.BOLD}{'=' * 80}{Colors.END}")
        output.append(f"{Colors.BOLD}{Colors.CYAN}Target: {result['hostname']}:{result['port']}{Colors.END}")
        output.append(f"{Colors.BOLD}{'=' * 80}{Colors.END}\n")

        if not result['success']:
            output.append(f"{Colors.RED}[!] Connection Failed: {result['error']}{Colors.END}\n")
            return '\n'.join(output)

        # PQC Status
        if result['pqc_detected']:
            output.append(f"{Colors.GREEN}{Colors.BOLD}[✓] POST-QUANTUM CRYPTOGRAPHY DETECTED{Colors.END}")
            for summary in result['pqc_summary']:
                output.append(f"{Colors.GREEN}    {summary}{Colors.END}")
        else:
            output.append(f"{Colors.YELLOW}[!] No Post-Quantum Cryptography Detected (Classical crypto only){Colors.END}")

        output.append("")

        # SSL/TLS Version
        output.append(f"{Colors.BOLD}SSL/TLS Information:{Colors.END}")
        output.append(f"  Protocol Version: {Colors.CYAN}{result['ssl_version']}{Colors.END}")

        # Cipher Suite
        if result['cipher_suite']:
            output.append(f"\n{Colors.BOLD}Cipher Suite:{Colors.END}")
            output.append(f"  Name: {Colors.CYAN}{result['cipher_suite']['name']}{Colors.END}")
            output.append(f"  Protocol: {result['cipher_suite']['protocol']}")
            output.append(f"  Strength: {result['cipher_suite']['bits']} bits")

            if result['cipher_analysis']:
                ca = result['cipher_analysis']
                if ca['pqc_detected']:
                    output.append(f"  {Colors.GREEN}PQC Status: POST-QUANTUM{Colors.END}")
                    if ca['is_hybrid']:
                        output.append(f"  {Colors.CYAN}Type: Hybrid (PQC + Classical){Colors.END}")
                    for algo, matches in ca['pqc_algorithms'].items():
                        output.append(f"    - {algo}: {', '.join(matches)}")
                else:
                    output.append(f"  {Colors.YELLOW}PQC Status: Classical only{Colors.END}")

                if ca['classical_algorithms']:
                    output.append(f"  Classical algorithms: {', '.join(ca['classical_algorithms'].keys())}")

        # Key Exchange Group (from OpenSSL)
        if result.get('openssl_info') and result['openssl_info'].get('success'):
            openssl = result['openssl_info']
            if openssl.get('negotiated_group'):
                output.append(f"\n{Colors.BOLD}Key Exchange:{Colors.END}")
                group = openssl['negotiated_group']
                output.append(f"  Negotiated Group: {Colors.CYAN}{group}{Colors.END}")

                if openssl.get('pqc_detected'):
                    output.append(f"  {Colors.GREEN}Group Type: POST-QUANTUM HYBRID{Colors.END}")
                    for algo, matches in openssl.get('pqc_algorithms', {}).items():
                        output.append(f"    - {algo}: {', '.join(matches)}")
                else:
                    output.append(f"  {Colors.YELLOW}Group Type: Classical{Colors.END}")

        # Certificate Information
        if result['certificate'] and CRYPTOGRAPHY_AVAILABLE:
            cert = result['certificate']
            output.append(f"\n{Colors.BOLD}Certificate Information:{Colors.END}")

            if 'commonName' in cert['subject']:
                output.append(f"  Subject CN: {cert['subject']['commonName']}")
            if 'organizationName' in cert['subject']:
                output.append(f"  Organization: {cert['subject']['organizationName']}")

            if 'commonName' in cert['issuer']:
                output.append(f"  Issuer CN: {cert['issuer']['commonName']}")

            output.append(f"  Valid From: {cert['not_valid_before']}")
            output.append(f"  Valid Until: {cert['not_valid_after']}")
            output.append(f"  Signature Algorithm: {Colors.CYAN}{cert['signature_algorithm']}{Colors.END}")

            public_key_info = f"  Public Key: {cert['public_key_algorithm']}"
            if cert['public_key_size']:
                public_key_info += f" ({cert['public_key_size']} bits)"
            output.append(public_key_info)

            if cert.get('pqc_detected'):
                output.append(f"  {Colors.GREEN}Certificate uses PQC algorithms!{Colors.END}")
                for algo, matches in cert.get('pqc_algorithms', {}).items():
                    output.append(f"    - {algo}: {', '.join(matches)}")

        output.append(f"\n{Colors.BOLD}{'-' * 80}{Colors.END}")

        return '\n'.join(output)

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL for PQC support"""
        hostname, port = self.parse_url(url)

        if self.verbose:
            print(f"[*] Analyzing {hostname}:{port}...")

        result = self.get_ssl_info(hostname, port)
        return result

    def analyze_urls_from_file(self, filename: str) -> List[Dict[str, Any]]:
        """Analyze multiple URLs from a file"""
        results = []

        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            print(f"[*] Found {len(urls)} URLs to analyze\n")

            for i, url in enumerate(urls, 1):
                print(f"[*] [{i}/{len(urls)}] Analyzing {url}...")
                result = self.analyze_url(url)
                results.append(result)

        except FileNotFoundError:
            print(f"{Colors.RED}[!] Error: File '{filename}' not found{Colors.END}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading file: {e}{Colors.END}")
            sys.exit(1)

        return results


def main():
    parser = argparse.ArgumentParser(
        description='sslq - SSL/TLS Post-Quantum Cryptography Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -u https://cloudflare.com
  %(prog)s -u example.com:443
  %(prog)s -f urls.txt
  %(prog)s -f urls.txt -j results.json
  %(prog)s -u google.com --timeout 15 --verbose
        '''
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single URL to analyze')
    group.add_argument('-f', '--file', help='File containing URLs (one per line)')

    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-j', '--json', help='Save results to JSON file')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')

    # Create detector instance
    detector = PQCDetector(timeout=args.timeout, verbose=args.verbose)

    # Analyze URL(s)
    results = []
    if args.url:
        result = detector.analyze_url(args.url)
        results.append(result)
        print(detector.format_output(result))
    elif args.file:
        results = detector.analyze_urls_from_file(args.file)
        for result in results:
            print(detector.format_output(result))

    # Summary
    if len(results) > 1:
        pqc_count = sum(1 for r in results if r.get('pqc_detected'))
        success_count = sum(1 for r in results if r.get('success'))

        print(f"\n{Colors.BOLD}Summary:{Colors.END}")
        print(f"  Total analyzed: {len(results)}")
        print(f"  Successful connections: {success_count}")
        print(f"  {Colors.GREEN}PQC detected: {pqc_count}{Colors.END}")
        print(f"  {Colors.YELLOW}Classical only: {success_count - pqc_count}{Colors.END}")

    # Save to JSON if requested
    if args.json:
        try:
            with open(args.json, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n{Colors.GREEN}[✓] Results saved to {args.json}{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error saving JSON: {e}{Colors.END}")


if __name__ == '__main__':
    main()
