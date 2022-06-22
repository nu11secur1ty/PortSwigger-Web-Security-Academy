### A small useful template =)


## Info for the key =)
---key---
---key---
to Base64


### Need
- login token

```
'eyJraWQiOiIyNTNmZjc1NC1lNjU1LTRiNjMtYTQzYy1kMDEzYWYyNjYxNjYiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTg5MDU3NH0.iDlTP_WXGNJepVbPTRnT5mKHgSoojI6X8V6QYczDPWjgZgqIPH5RFnnr2orq17YSJmPAFNqtxuLwfjNdPOP93sTAHOCuBKtYlzmff9tXYm0c6VW8Elu4r6IDSyVD2sNKHJhamtf7e2GVhNeyfHvLO9J_Bl8nw_jtBOAshg0LErA_G9RULvbYMmLpHKXX2M5HpqY7loPa4Eb9uxdKjQtWFxyWg1Tf4fBCpZJWxRb5CJW90Urn4VGftbNDNYQqPDFyVFLEAfi5kGFDJUqrldF4Xb6_gGDNgN6kdO_RRf0EQQStd2tXlZcLoKFiZWA9NA0QhBKU1e8N_fXOGdkWsyoIEw'
```
- my-account token

```
'eyJraWQiOiIyNTNmZjc1NC1lNjU1LTRiNjMtYTQzYy1kMDEzYWYyNjYxNjYiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTg5MDU2NX0.QVy15MbqFXF_87vmW_ed7eXuBWISMFrRrAaUJ9Frvj4FtTbNJ7GkEC-Wt6pHvQZmLVrh7i7IcLdlPU08SL8Qpd9As2-G6UIzFdFx2NVOMZvz-1xgyYVdzOY_RltkGltTbgyBYC6X99hohhonctKuxjoEp0LRpazV7Egs-YNFqy9oZ2E0_s3nod_lv_iyP-_paAxPKXx6RWm4nhORFWrRFAFrbakMss41a3gbay3HISsGJa70TfTamMZHImmhlAsu2nHFl7NpRMCLPwqbd8weVOeDFuiv2OtXTDM8e8O3fDQtxGZZZ9e_tzuSJWQXH3vBl2KTINGdBSKFiDeXJbqr0g'
```

Test key if is ok

```GET
/my-account
```
Output: `response 200`


### Docker

```URL
https://github.com/silentsignal/rsa_sign2n
```

# Build
sudo docker build . -t sig2n

# Run docker
sudo docker run -it sig2n /bin/bash
