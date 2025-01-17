# Office 365 User Enumeration

Enumerate valid usernames from Office 365 using the office.com login page while optionally dodging throttling by rotating IPs with each request through Fireprox APIs.

# WARNING! This Repository Is Deprecated

> This repository is now considered deprecated and will no longer receive further support. This tool has been refactored into a module within Stratustryke (https://github.com/vexance/Stratustryke). Refer to the Stratustryke repository and leverage the `m365/enum/unauth/m365_enum_users_managed` module for similar functionality.

## Usage

o365enum will read usernames from the file provided as first parameter. The file should have one username per line.

```
python3 o365enum.py --help
usage: o365enum.py [-h] [-u USERS] [-d DOMAIN] [--static] [-v] [-o OUTFILE] [--profile PROFILE] [--access-key ACCESS_KEY] [--secret-key SECRET_KEY] [--session-token SESSION_TOKEN] [--region REGION] command

Office365 User Enumeration Script

positional arguments:
  command               Module / command to run [list,delete,enum]

optional arguments:
  -h, --help            show this help message and exit
  -u USERS, --users USERS
                        Required for 'enum' module; File containing list of users / emails to enumerate
  -d DOMAIN, --domain DOMAIN
                        Email domain if not already included within user file
  --static              Disable IP rotation via Fireprox APIs; O365 will throttle after ~100 requests
  -v, --verbose         Enable verbose output at urllib level
  -o, --outfile         File to output results to [default: None]
  --profile PROFILE     AWS profile within ~/.aws/credentials to use [default: default]
  --access-key ACCESS_KEY
                        AWS access key id for fireprox API creation
  --secret-key SECRET_KEY
                        AWS secret access key for fireprox API creation
  --session-token SESSION_TOKEN
                        AWS session token for assumed / temporary roles
  --region REGION       AWS region to which fireprox API will be deployed [default: us-east-1]
```

Example O365 username enumeration
```
./o365enum.py enum -u users.txt
Creating => https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US...
[2021-09-09 22:07:00-04:00] (abcdefghijklmno) fireprox_microsoftonline => https://abcdefghijklmno.execute-api.us-east-1.amazonaws.com/fireprox/ (https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US)
[-] first.last@example.com - Invalid user
[*] flast@example.com - Valid user with different IDP
[-] first.last2@example.com - Invalid user
[+] flast2@example.com - Valid user
[+] flast3@example.com - Valid user
[!] f.last@nonexistant.example.com. - Domain type 'UNKNOWN' not supported
[+] flast4@example.com - Valid user
[-] first.last3@example.com - Invalid user
[+] flast5@example.com - Valid user
[-] f.last2@example.com - Invalid user
[!] f.last3@example.com - Possible throttle detected on request
[-] f.last3@example.com - Invalid user
```

Example Fireprox API Listing
```
python3 o365enum.py list
[2021-09-09 22:05:34-04:00] (abcdefghijklmno) fireprox_microsoftonline: https://abcdefghijklmno.execute-api.us-east-1.amazonaws.com/fireprox/ => https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US/
```

Example Deleation of all Fireprox APIs
```
python3 o365enum.py delete
[+] Listing Fireprox APIs prior to deletion
[2021-09-09 22:05:34-04:00] (abcdefghijklmno) fireprox_microsoftonline: https://abcdefghijklmno.execute-api.us-east-1.amazonaws.com/fireprox/ => https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US/
[2021-09-09 22:07:00-04:00] (qwertyuiop) fireprox_microsoftonline: https://qwertyuiop.execute-api.us-east-1.amazonaws.com/fireprox/ => https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US/
[+] Attempting to delete API 'abcdefghijklmno'
[+] Attempting to delete API 'qwertyuiop'
[+] Fireprox APIs following deletion:
```
> __Note:__<br/>
> o365enum *should* automatically delete all Fireprox APIs when complete or in the event of an exception / keyboard interrupt during execution


## Office.com Enumeration

**WARNING**: This method only works for organization that are subscribers of Exchange Online and that do not have on-premise or hybrid deployment of Exchange server.

For companies that use on premise Exchange servers or some hybrid deployment and based on some configuration I haven't identified yet, the script will return DOMAIN_NOT_SUPPORTED.

### Throttling

Based on testing, Office.com will allow 100 user checks before you are throttled. Once throttling has started, Office.com will start to give a
VALID_USER response to each request. 

### Existing User

When the account exists, `IfExistsResult` is set to 0, 5, or 6.

```
POST /common/GetCredentialType?mkt=en-US HTTP/1.1
Host: login.microsoftonline.com
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36
Accept: application/json
Connection: close
client-request-id: 4345a7b9-9a63-4910-a426-35363201d503
hpgrequestid: 23975ac9-f51c-443a-8318-db006fd83100
Referer: https://login.microsoftonline.com/common/oauth2/authorize
canary: --snip--
hpgact: 1800
hpgid: 1104
Origin: https://login.microsoftonline.com
Cookie: --snip--
Content-Length: 1255
Content-Type: application/json

{
    "checkPhones": false,
    "isOtherIdpSupported": true,
    "isRemoteNGCSupported": true,
    "federationFlags": 0,
    "isCookieBannerShown": false,
    "isRemoteConnectSupported": false,
    "isSignup": false,
    "originalRequest": "rQIIA--snip--YWSO2",
    "isAccessPassSupported": true,
    "isFidoSupported": false,
    "isExternalFederationDisallowed": false,
    "username": "existing@contoso.com",
    "forceotclogin": false
}
```

```
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
client-request-id: 177110da-7ce4-4880-b856-be6326078046
x-ms-request-id: c708b83f-4167-4b4c-a1db-d2011ecb3200
x-ms-ests-server: 2.1.9966.8 - AMS2 ProdSlices
Referrer-Policy: strict-origin-when-cross-origin
P3P: CP="DSP CUR OTPi IND OTRi ONL FIN"
Set-Cookie: fpc=ArU-Dva0f59Eg4t_V3VsX_TsYIXWAQAAAFRGxtUOAAAA; expires=Sun, 01-Mar-2020 16:01:26 GMT; path=/; secure; HttpOnly; SameSite=None
Set-Cookie: x-ms-gateway-slice=prod; path=/; SameSite=None; secure; HttpOnly
Set-Cookie: stsservicecookie=ests; path=/; secure; HttpOnly; SameSite=None
Date: Fri, 31 Jan 2020 16:01:26 GMT
Connection: close
Content-Length: 587

{
    "Username":"existing@contoso.com",
    "Display":"existing@contoso.com",
    "IfExistsResult":0,
    "ThrottleStatus":0,
    "Credentials":{
        "PrefCredential":1,
        "HasPassword":true,
        "RemoteNgcParams":null,
        "FidoParams":null,
        "SasParams":null
    },
    "EstsProperties":{
        "UserTenantBranding":null,
        "DomainType":3
    },
    "IsSignupDisallowed":true,
    "apiCanary":"--snip--"
}
```

#### Nonexistent User

When the account does not exist, `IfExistsResult` is set to 1.

```
POST /common/GetCredentialType?mkt=en-US HTTP/1.1
Host: login.microsoftonline.com
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36
Accept: application/json
Connection: close
client-request-id: 4345a7b9-9a63-4910-a426-35363201d503
hpgrequestid: 23975ac9-f51c-443a-8318-db006fd83100
Referer: https://login.microsoftonline.com/common/oauth2/authorize
canary: --snip--
hpgact: 1800
hpgid: 1104
Origin: https://login.microsoftonline.com
Cookie: --snip--
Content-Length: 1255
Content-Type: application/json

{
    "checkPhones": false,
    "isOtherIdpSupported": true,
    "isRemoteNGCSupported": true,
    "federationFlags": 0,
    "isCookieBannerShown": false,
    "isRemoteConnectSupported": false,
    "isSignup": false,
    "originalRequest": "rQIIA--snip--YWSO2",
    "isAccessPassSupported": true,
    "isFidoSupported": false,
    "isExternalFederationDisallowed": false,
    "username": "nonexistent@contoso.com",
    "forceotclogin": false
}
```

```
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
client-request-id: 95bba645-c3b0-4566-b0f4-237bd3df2ca7
x-ms-request-id: fea01b74-7a60-4142-a54d-7aa8f6471c00
x-ms-ests-server: 2.1.9987.14 - WEULR2 ProdSlices
Referrer-Policy: strict-origin-when-cross-origin
P3P: CP="DSP CUR OTPi IND OTRi ONL FIN"
Set-Cookie: fpc=Ai0TKYuyz3BCp7OL29pUnG7sYIXWAQAAABsDztUOAAAA; expires=Sat, 07-Mar-2020 12:57:44 GMT; path=/; secure; HttpOnly; SameSite=None
Set-Cookie: x-ms-gateway-slice=estsfd; path=/; SameSite=None; secure; HttpOnly
Set-Cookie: stsservicecookie=ests; path=/; secure; HttpOnly; SameSite=None
Date: Thu, 06 Feb 2020 12:57:43 GMT
Connection: close
Content-Length: 579


{
    "ThrottleStatus": 0,
    "apiCanary": "--snip--",
    "Username": "nonexistent@contoso.com",
    "IfExistsResult": 1,
    "EstsProperties": {
        "UserTenantBranding": null,
        "DomainType": 3
    },
    "Credentials": {
        "PrefCredential": 1,
        "FidoParams": null,
        "RemoteNgcParams": null,
        "SasParams": null,
        "HasPassword": true
    },
    "IsSignupDisallowed": true,
    "Display": "nonexistent@contoso.com"
}
```

## Contributors

* [@jenic](https://github.com/jenic) - Arguments parsing and false negative reduction.
* [@gremwell](https://github.com/gremwell) - Original script author
* [@BarrelTit0r](https://github.com/BarrelTit0r) - Enhancement and refinement of user enumeration functionality
* [@Vexance](https://github.com/vexance) - IP rotation through FireProx APIs and outfile / output reformatting
