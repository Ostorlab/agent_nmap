`Secure` cookie: is only sent to the server with an encrypted request
over the HTTPS protocol. Cookies missing the `Secure` flag can be sent
over unencrypted channels. The flag's presence should not justify
the storage of sensitive data, as the flag remains an unsafe place to
store data.

`HttpOnly` cookie: helps mitigate cross-site scripting (XSS)
vulnerabilities, `HttpOnly` cookies are inaccessible from javascript
using the `document.cookie` API.

```http request
Set-Cookie: id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Secure; HttpOnly
```
