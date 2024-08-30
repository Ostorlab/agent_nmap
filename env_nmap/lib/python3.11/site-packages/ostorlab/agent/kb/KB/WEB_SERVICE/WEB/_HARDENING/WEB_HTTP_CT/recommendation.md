- When serving resources, make sure you send the content-type header to appropriately match the type of the resource
  being served. For example, if you are serving an HTML page, you should send the HTTP header:

```html
Content-Type: text/html
```

- Add the X-Content-Type-Options header with a value of "nosniff" to inform the browser to trust what the site has sent
  is the appropriate content-type, and to not attempt "sniffing" the real content-type.

```html
X-Content-Type-Options: nosniff
```