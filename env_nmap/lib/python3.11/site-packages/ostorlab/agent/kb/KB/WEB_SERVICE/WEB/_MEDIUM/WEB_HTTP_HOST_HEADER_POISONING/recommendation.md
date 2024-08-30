Protection against Host header attacks will require multiple checks that depend on the application target architecture,
like support for a virtual host, use of a reverse proxy, and presence in certain cloud environments, the support extra
routing headers.

The recommendations to protect against these attacks are:

* Avoid using the `Host` header value in application logic.
* Implement a whitelist check of accepted values; most web frameworks commonly support this.
* Disable host override headers; this depends on the intermediary components deployed in your architecture. Common
  places to check are reverse-proxies and Kubernetes ingress controllers.
