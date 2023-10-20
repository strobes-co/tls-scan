import asyncio
import ipaddress
import time
import argparse
from .helpers import create_ssl_context
import hashlib

COMMON_SSL_PORTS = [443, 8443, 8080, 9443]


def format_subject(subject):
    return ', '.join('='.join(pair) for pair in subject[0])


async def get_cert_details(semaphore: asyncio.Semaphore, ip: str, port: int) -> dict:
    async with semaphore:
        ctx = create_ssl_context()
        start_time = time.time()

        conn = asyncio.open_connection(ip, port, ssl=ctx)
        _, writer = await asyncio.wait_for(conn, timeout=3)

        peercert = writer.get_extra_info("peercert")
        session = writer.get_extra_info('ssl_object')
        end_time = time.time()
        writer.close()
        await writer.wait_closed()
        if not peercert:
            return {}

        cert_der = session.getpeercert(binary_form=True)
        md5_fingerprint = hashlib.md5(cert_der).hexdigest()
        sha1_fingerprint = hashlib.sha1(cert_der).hexdigest()
        sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()

        details = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime()),
            "host": ip,
            "ip": ip,
            "port": port,
            "elapsedTime": (end_time - start_time) * 1000,
            "tlsVersion": session.version(),
            "cipher": session.cipher()[0],
            "mismatched": ip != peercert['subject'][0][0][1],
            "not_before": peercert['notBefore'],
            "not_after": peercert['notAfter'],
            "subject_dn": format_subject(peercert['subject']),
            "subject_cn": peercert['subjectAltName'][0][1] if 'subjectAltName' in peercert else None,
            "subject_org": [item[0][1] for item in peercert['subject'] if item[0][0] == 'organizationName'],
            "subject_an": [item[1] for item in peercert['subjectAltName'] if item[0] == 'DNS'] if 'subjectAltName' in peercert else [],
            "serial": peercert['serialNumber'],
            "issuer_dn": format_subject(peercert['issuer']),
            "issuer_cn": peercert['issuer'][0][0][1],
            "issuer_org": [item[0][1] for item in peercert['issuer'] if item[0][0] == 'organizationName'],
            "fingerprint_hash": {
                "md5": md5_fingerprint,
                "sha1": sha1_fingerprint,
                "sha256": sha256_fingerprint
            },
            "wildcard_certificate": any([name.startswith('*.') for name in [item[1] for item in peercert['subjectAltName']]]) if 'subjectAltName' in peercert else False,
            "tls_connection": "ctls",  # Placeholder, adjust as needed.
            "sni": ip  # Placeholder, adjust as needed.
        }
        print(details)

        return details


async def async_main(cidr: str, concurrency: int):
    semaphore = asyncio.Semaphore(concurrency)
    ip_net = ipaddress.ip_network(cidr)
    tasks = [get_cert_details(semaphore, str(ip), port)
             for port in COMMON_SSL_PORTS for ip in ip_net]
    await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description="TLS Certificate Scanner")
    parser.add_argument(
        "cidr", type=str, help="CIDR range to scan. E.g., '192.168.0.0/24'")
    parser.add_argument("--concurrency", type=int, default=50,
                        help="Number of concurrent tasks")

    args = parser.parse_args()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main(args.cidr, args.concurrency))
    loop.close()


if __name__ == "__main__":
    main()
