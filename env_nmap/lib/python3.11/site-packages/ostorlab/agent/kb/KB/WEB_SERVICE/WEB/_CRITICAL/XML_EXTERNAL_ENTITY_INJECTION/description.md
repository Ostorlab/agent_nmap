XXE (XML External Entity) injection is a critical security flaw that arises when an application parses XML input from untrusted sources without proper validation. Attackers exploit this vulnerability by injecting external entities into the XML data, potentially leading to unauthorized access to sensitive files or directories on the server, such as /etc/passwd. This breach can enable adversaries to extract confidential information, disrupt application functionality, or execute arbitrary code. XXE vulnerabilities commonly occur due to lax input validation and the misconfiguration of XML parsers, allowing malicious entities to manipulate XML structures.
### Examples

#### Java

```java
//Input example : 
String xmlInput = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" +
    "<foo>&xxe;</foo>";

DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new ByteArrayInputStream(xmlInput.getBytes()));

// Process the XML document
// Access the parsed data, which could potentially include sensitive information
```

#### Javascript

```javascript
const app = require("express")();
const libxml = require("libxmljs");
app.post("/path", (req, res) => {
  Element = libxml.parseXml(req.body, { noent: true });
 // Processing the XML element
});
```

#### Php

```php
<?php
$xmlInput = '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>';

$doc = new DOMDocument();
$doc->loadXML($xmlInput);

echo $doc->saveXML();
?>

```

