This docker image use for testing application using JWT and x509 public key endpoint, something like Google Firebase authentication.  

## Usage
```sh
docker run --name test_name -it -p 8080:8080 fake_token:1.0.0
```

* Public key endpoint: http://localhost:8080/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
* Token generate endpoint: http://localhost:8080/token with parameters:  
    * **kid**: specific the key (returned from public key endpoint) for signing, if not set then use a random key to sign
    * **IssuerPrefix**: usage in token template
    * **Audience**: usage in token template
    * **AuthTime**: if not set `UnixSecond(now - 1 min)`
    * **UserID**: if not set `UnixNano(now)`
    * **IssueAt**: if not set `UnixSecond(now)`
    * **Expiration**: if not set `UnixSecond(now)`
    * **PhoneNumber**: if not set `"+84"+UnixSecond(now)`

## Config
```
ENV PORT=":8080"
ENV KEYS_PATTERN="./private_pems/*.pem"
ENV TOKEN_TEMPLATE="./token.template"
```