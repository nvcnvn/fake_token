This docker image use for testing application using JWT and x509 cert endpoint, something like Google Firebase authentication.  
Docker repo: https://hub.docker.com/r/nvcnvn/fake_token

## Usage
```sh
docker pull nvcnvn/fake_token:1.0.0
docker run --name test_name -it -p 8080:8080 nvcnvn/fake_token:1.0.0
```

* Cert endpoint: http://localhost:8080/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
* Token generate endpoint: http://localhost:8080/token with parameters:  
    * **kid**: specific the key (returned from cert endpoint) for signing, if not set then use a random key to sign
    * **IssuerPrefix**: use in token template, default value can be set in template
    * **Audience**: use in token template, default value can be set in template
    * **AuthTime**: if not set `UnixSecond(now - 1 min)`
    * **UserID**: if not set `UnixNano(now)`
    * **IssueAt**: if not set `UnixSecond(now)`
    * **Expiration**: if not set `UnixSecond(now + 1 hour)`
    * **PhoneNumber**: if not set `"+84"+UnixSecond(now)`

## Config
```
ENV PORT=":8080"
ENV KEYS_PATTERN="./private_pems/*.pem"
ENV TOKEN_TEMPLATE="./token.template"
ENV CERT_NOT_BEFORE="Jan 2 15:04:05 2006" // use for fake cert
ENV CERT_NOT_AFTER="Jan 2 15:04:05 2026" // use for fake cert
```
