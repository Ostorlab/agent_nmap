The HTTP Host specifies the domain name the HTTP Client would like to access. It is mandatory as part of the HTTP/1.1
standard.

For instance, to access the domain `www.ostorlab.co`, the HTTP client would send the following request with the `Host`
header:

```http request
GET / HTTP/1.1
Host: www.ostorlab.co
```

The `Host` header is important to enabling routing traffic to virtual hosts.

Applications that handle the `Host` header insecurely are vulnerable to multiple classes of vulnerabilities, like:

* Server-side request forgery
* Web Cache poisoning
* Insecure redirects

`Host` header poisoning can materialize in different ways:

* Arbitrary Host header reflection
* Duplicate Host headers injection
* Absolute URL injection and ignoring the Host header value
* Header injection by adding a line wrapper
* Injection of common Host override-headers, like `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`
