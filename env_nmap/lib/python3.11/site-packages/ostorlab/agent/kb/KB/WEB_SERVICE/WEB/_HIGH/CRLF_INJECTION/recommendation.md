- __Upgrade to the latest software version__: CRLF injection usually impacts the webserver or the reverse proxy itself, therefore it's advised to keep it up to date.
- __Avoid setting header name from user input__: Allowing users to control http header names can lead to several security issues including CRLF injection.
- __User input sanitization__: in some cases, it might be possible to achieve CRLF injection if the web application concatenates user input into response headers or cookies, therefore, user input should be sanitized from special characters. 

=== "Request"
  ```http
  GET /?page=login%0D%0ACustom-Header:%20vulnerable HTTP/1.1
  Host: localhost
  User-Agent: Mozilla/5.0
  Referrer: http://localhost/
  ```

=== "Response"
  ```http
  HTTP/1.1 200 OK
  Date: Wed, 05 Jan 2024 12:00:00 GMT
  Server: Apache/2.4.58 (Unix)
  Content-Length: 1234
  Content-Type: text/html; charset=UTF-8
  Set-Cookie: page=login%0D%0ACustom-Header:%20vulnerable
  
  <body>
  ```
