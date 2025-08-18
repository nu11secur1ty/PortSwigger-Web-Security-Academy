# Burp POST Body Smuggling Intruder Script – Documentation

**Author:** nu11secur1ty  
**Year:** 2025  
**Purpose:** Automate detection and exploitation of HTTP request smuggling vulnerabilities via Burp Intruder.

---

## Table of Contents

1. Introduction  
2. Requirements  
3. Setup  
4. Script Overview  
5. Technical Details  
6. Usage Instructions  
7. Payload Construction  
8. Attack Flow  
9. Response Handling  
10. Stop Condition  
11. Security Considerations  
12. References  
13. Full Python Script  

---

## 1. Introduction

This script leverages **HTTP request smuggling** vulnerabilities to deliver a crafted payload through Burp Suite Intruder. It automates sending specially crafted HTTP requests with **Content-Length manipulations** to detect server desynchronization issues.  

Unlike previous versions, **the script does not automatically stop** after the payload executes. The operator must manually terminate the attack after confirming success.

---

⚙️ Technical Analysis

The core of the attack leverages the Transfer-Encoding and Content-Length headers:
Transfer-Encoding: Specifies how the body of the request is encoded. The chunked transfer encoding allows the body to be sent in chunks, with each chunk preceded by its size.
Content-Length: Indicates the size of the request body in bytes.
When both headers are present, different servers may interpret them differently. For instance, a front-end proxy might prioritize Content-Length, while a back-end server might prioritize Transfer-Encoding. This discrepancy can lead to the back-end server receiving a request that the front-end server has already processed, allowing the attacker to smuggle additional requests .
In the provided script, the kurnabiva1 request is designed to be processed by the front-end server, while kurnabiva2 and smuggled are intended for the back-end server. The victim request helps determine if the payload has been executed.


🛡️ Security Implications

Exploiting HRS vulnerabilities can have severe consequences:
Bypassing Security Controls: Attackers can bypass firewalls, proxies, and other security mechanisms.
Cross-Site Scripting (XSS): Malicious scripts can be injected into responses, leading to XSS attacks.
Session Hijacking: Attackers can steal session cookies or tokens, impersonating legitimate users.
Cache Poisoning: Malicious responses can be cached and served to other users.

🛠️ Mitigation Strategies

To protect against HRS attacks:
Consistent Header Parsing: Ensure that both front-end and back-end servers interpret Content-Length and Transfer-Encoding headers consistently.
Disable Connection Reuse: Prevent reusing connections between front-end and back-end servers to avoid desynchronization.
Use HTTP/2: HTTP/2 has improved handling of request parsing, reducing the likelihood of HRS vulnerabilities.
Implement Web Application Firewalls (WAFs): Configure WAFs to detect and block malicious request patterns.
Regular Security Audits: Conduct regular security assessments to identify and remediate potential vulnerabilities.

🧪 Conclusion

The provided Burp Suite Intruder script is a sophisticated tool for automating the exploitation of HTTP request smuggling vulnerabilities. 
By understanding its components and the underlying attack vectors, security professionals can better defend against such threats. 
Regular updates to security practices and tools are essential to stay ahead of emerging vulnerabilities and attack techniques.

## 2. Requirements

- Burp Suite Professional with Intruder module  
- Python 3.x for script execution  
- Network access to the target host  
- Knowledge of HTTP request smuggling techniques  

---

## 3. Setup

1. Place `0.CL-request-smuggling-XSS.py` in Burp Suite Extender scripts directory.  
2. Configure Intruder to use this script as the payload engine.  
3. Define the `host` variable dynamically using Burp’s target scope.  

---

## 4. Script Overview

- **Global Flag:** `stop_attack` – included but **does not auto-stop** the attack.  
- **Functions:**  
  - `queueRequests(target, wordlists)` – sends the crafted requests.  
  - `handleResponse(req, interesting)` – monitors responses but only logs payload execution.  

---

## 5. Technical Details

The attack consists of three stages:

1. **kurnabiva1** – Initial POST request to a target endpoint with adjustable `Content-Length`.  
2. **kurnabiva2** – GET requests injected with a payload to trigger XSS or other desync vulnerabilities.  
   - `kurnabiva2_chopped` – preliminary request fragment.  
   - `kurnabiva2_revealed` – final part combined with the smuggled request.  
3. **victim** – Standard GET request to detect if the payload executed.  

---

## 6. Usage Instructions

1. Start Burp Suite and target the host you want to test.  
2. Load the script into Intruder’s `Payload Processing` section.  
3. Execute the attack.  
4. Monitor console output for `[+] Donne, your exploit is finished!` – indicates payload execution.  
5. **Manually stop Intruder** once success is confirmed.  

---

## 7. Payload Construction

- **Smuggled Request:**  

```http
GET /post?postId=10 HTTP/1.1
User-Agent: yu5md"><script>alert(1)</script>hgpov
user-agent: yu5md"><script>alert(1)</script>hgpov
X: Y
```


- Encodes an XSS payload in both HTTP/1.1 and HTTP/2 headers.
- Integrated into kurnabiva2_revealed for desync exploitation.

8. Attack Flow

queueRequests:

```
Send kurnabiva1 with manipulated Content-Length
Send kurnabiva2 (chopped + revealed + smuggled)
Send victim request to detect execution
Repeat until operator stops Intruder manually
```


9. Response Handling

- Each response is added to the global table.
- The script logs when the payload executes by detecting the marker hgpov in victim responses.
- Does not stop automatically – operator must manually halt Intruder

10. Stop Condition

```python
if req.label == 'victim' and 'hgpov' in req.response:
    print("[+] Done, your exploit is finished!")
```


- Logs payload execution to console.
- Manual intervention required to stop attack.


11. Security Considerations

- Use only on authorized targets or in lab environments.
- HTTP request smuggling can have unintended consequences on production systems.
- Payloads may trigger XSS or other vulnerabilities; handle outputs safely.


12. References

- PortSwigger Research: [HTTP/1 Must Die](https://portswigger.net/research/http1-must-die)
- 0.CL Lab examples and learning materials


13. Full Python Script by @nu11secur1ty

- Find it on the www.... ;)

