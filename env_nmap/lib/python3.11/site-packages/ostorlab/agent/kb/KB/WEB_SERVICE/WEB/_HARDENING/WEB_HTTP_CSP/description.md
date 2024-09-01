Content Security Policy (CSP) is a computer security standard that provides an added layer of protection against
Cross-Site Scripting (XSS), clickjacking, and other client-side attacks that rely on executing malicious content in the
context of a trusted web resource.

You can selectively specify which data sources should be
permitted in your web application using appropriate CSP directives in HTTP response headers. This article shows how to
use CSP headers to protect websites against XSS attacks and
other attempts to bypass the same-origin policy.

CSP can be enabled by instructing the browser with a Content-Security-Policy directive in a response header;

```html
 Content-Security-Policy: script-src 'self';
```

or in a meta tag;

```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self';"> 
```

You can restrict script loading only to the same domain in the above example. It will also limit inline script
executions in the element attributes and the event handlers. There are various directives that you can use by
declaring CSP:

- script-src: Restricts the script loading resources to the ones you declared. By default, it disables inline script
  executions unless you permit the evaluation functions and inline scripts by the unsafe-eval and unsafe-inline
  keywords.
- base-uri: The base element is used to resolve a relative URL to an absolute one. By using this CSP directive, you can
  define all possible URLs which could be assigned to the base-href attribute of the document.
  frame-ancestors: It is very similar to X-Frame-Options HTTP header. It defines the URLs by which the page can be
  loaded in an iframe.
- frame-src / child-src: frame-src is the deprecated version of child-src. Both define the sources that can be loaded by
  iframe on the page. (Please note that frame-src was brought back in CSP 3)
- object-src : Defines the resources that can be loaded by embedding such as Flash files, Java Applets.
- img-src: As its name implies, it defines the resources from which the images can be loaded.
- connect-src: Defines the whitelisted targets for XMLHttpRequest and WebSocket objects.
- default-src: It is a fallback for the directives that mostly end with -src suffix. When the directives below are not
  defined, the value set to default-src will be used instead:
    - child-src
    - connect-src
    - font-src
    - img-src
    - manifest-src
    - media-src
    - object-src
    - script-src
    - style-src
      When setting the CSP directives, you can also use some CSP keywords:

- none: Denies loading resources from anywhere.
- self : Points to the document's URL (domain + port).
- unsafe-inline: Permits running inline scripts.
- unsafe-eval: Permits execution of evaluation functions such as eval().

In addition to CSP keywords, you can use wildcard or only a scheme when defining whitelist URLs for the points.
Wildcard can be used for subdomain and port portions of the URLs:

```html
Content-Security-Policy: script-src https://*.ostorlab.com;
```

```html
Content-Security-Policy: script-src https://ostorlab.com:*;
```

```html
Content-Security-Policy: script-src https://ostorlab.com:*;
```

It is also possible to set a CSP in Report-Only mode instead of forcing it immediately in the migration period. Thus you
can see the violations of the CSP policy in the current state of your web site while migrating to CSP:

```html
Content-Security-Policy-Report-Only: script-src 'self'; report-uri: https://ostorlab.com;
```

### CSP Browser Support

Content Security Policy is supported by all the major modern browsers, and has been for many years. It is not supported in Internet Explorer.

- ### Chrome:
  - Content-Security-Policy CSP `Level 3` - `Chrome 59+` **Partial Support**
  - Content-Security-Policy CSP `Level 2` - `Chrome 40+` **Full Support Since January 2015**
  - Content-Security-Policy CSP `1.0` - `Chrome 25+`
  - X-Webkit-CSP **Deprecated** - `Chrome 14-24`
- ### Firefox:
  - Content-Security-Policy CSP `Level 3` - `Firefox 58+` **Partial Support**
  - Content-Security-Policy CSP `Level 2` - `Firefox 31+` **Partial Support since July 2014**
  - Content-Security-Policy CSP `1.0` - `Firefox 23+` **Full Support**
  - X-Content-Security-Policy **Deprecated** - `Firefox 4-22`
- ### Safari:
  - Content-Security-Policy CSP `Level 3` - `Safari 15.4+` **Partial Support**
  - Content-Security-Policy CSP `Level 2` - `Safari 10+`
  - Content-Security-Policy CSP `1.0` - `Safari 7+`
  - X-Webkit-CSP **Deprecated** `Safari 6`
- ### Edge:
  - Content-Security-Policy CSP `Level 3` - `Edge 79+` **Partial Support**
  - Content-Security-Policy CSP `Level 2` - `Edge 15+` **Partial, 76+ Full**
  - Content-Security-Policy CSP `1.0` - `Edge 12+`
- ### Internet Explorer:
  - X-Content-Security-Policy **Deprecated** - `IE 10-11` support sandbox only
