- Enable CSP on your website by sending the Content-Security-Policy in HTTP response headers that instruct the browser
  to apply the policies you specified.
- Apply the whitelist and policies as strictly as possible.
- Rescan your application to see if Ostorlab identifies any weaknesses in your policies.
- Use frame-src to prevent iFrames from loading on your site: `Content-Security-Policy:frame-src 'none'`
- Use script-src to prevent JavaScript from loading on your site: `Content-Security Policy:script-src 'none'`
- Restrict content other than images with img-src: `Content-Security-Policy: default-src 'self'; img-src *;`
- Use default-src to allow only content to load from the same origin, your website, and its subdomains: `Content-Security-Policy: default-src 'self' *.sucuri.net;`
- Only allow media or other executable scripts from same origin: `Content-Security-Policy: default-src 'self'; img-src *; media-src sucuri.net; script-src sucuri.net;`
- Only allow images, scripts, form actions and CSS from same origin: `default-src 'none'; script-src 'self'; img-src 'self'; style-src 'self';base-uri 'self';form-action 'self'`
