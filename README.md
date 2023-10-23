# TLS Certificate Scanner

This project is a Python-based tool that efficiently scans a range of IP addresses, fetches the SSL/TLS certificates of servers on common SSL ports, and then prints the details of these certificates.

## Features:

- Asynchronous scanning of IP addresses for speed and efficiency.
- Retrieves details like:
  - Timestamp of scan
  - TLS Version
  - Cipher details
  - Subject details (DN, CN, Organization, Alternate Names)
  - Issuer details
  - Certificate Validity
  - Fingerprint hash (MD5, SHA1, SHA256)
  - Check for wildcard certificates

- Can scan CIDR range (e.g., `192.168.0.0/24`) for SSL/TLS-enabled servers.

## Prerequisites:

- Python 3.7+
- Additional dependencies can be found in the `requirements.txt` (if provided).

## Usage:

1. Clone the repository:

```bash
git clone https://github.com/strobes-co/tls-scan.git
cd tls-scan
python3 setup.py install
```

2. (Optional) Install dependencies if they exist:

```bash
pip install -r requirements.txt
```

3. Run the script:

```bash
tls_scan <CIDR> [--concurrency <num_of_concurrent_tasks>]
```

For example:

```bash
tls_scan 192.168.0.0/24 --concurrency 100
```

## Arguments:

- `cidr`: The CIDR range to scan. For instance, '192.168.0.0/24'.
- `--concurrency`: (Optional) Number of concurrent tasks. Default is 50.

## Note:

- The tool only prints the results to the console for now. Future versions might include options to save to a file or a database.
- Always make sure to have the required permissions to scan the target IPs. Unauthorized scanning can be illegal.

## Contributions:

Feel free to fork this project, open issues, or submit pull requests. Your contributions are welcome!

## License:

This project is licensed under the MIT License. Refer to the `LICENSE` file for more details.

