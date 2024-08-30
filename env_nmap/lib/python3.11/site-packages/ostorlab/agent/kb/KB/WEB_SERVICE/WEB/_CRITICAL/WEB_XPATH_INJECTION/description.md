XPath injection is a type of attack that can change the intent of an XPath query that is executed on an application’s backend. An application might be vulnerable to this attack if special characters are injected into a user-supplied input value, that input is not filtered and is concatenated with other strings to construct an XPath query, which is executed against an XML document.

Impacts of this attack can include bypassing authentication logic, or the disclosure of sensitive data within the XML document being queried.

### Examples

#### Java

```java
 String xmlInput = "<users>" +
            "<user><username>admin</username><password>admin@123</password></user>" +
            "<user><username>guest</username><password>guest@123</password></user>" +
            "</users>";

DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));

//Input example : 
String inputUsername = "admin' or '1'='1' or '";
String inputPassword = "randomPassword";

XPathFactory xPathfactory = XPathFactory.newInstance();
XPath xpath = xPathfactory.newXPath();

String query = String.format("//user[username/text()='%s' and password/text()='%s']", inputUsername, inputPassword);
XPathExpression expr = xpath.compile(query);

Object result = expr.evaluate(doc, XPathConstants.NODESET);
NodeList nodes = (NodeList) result;

System.out.println(nodes.getLength() > 0 ? "Authenticated" : "Authentication Failed");
```

#### Javascript

```javascript
const express = require('express');
const libxml = require('libxmljs');

const app = express();
const xmlInput = `<users>
  <user><username>admin</username><password>admin@123</password></user>
  <user><username>guest</username><password>guest@123</password></user>
</users>`;

app.post('/authenticate', (req, res) => {
  const { username, password } = req.body;

  const xmlDoc = libxml.parseXml(xmlInput);
  const query = `//user[username/text()='${username}' and password/text()='${password}']`;
  const nodes = xmlDoc.find(query);

  res.send(nodes.length > 0 ? 'Authenticated' : 'Authentication Failed');
});
```

#### Php

```php
<?php
$xmlInput = "<users>" .
    "<user><username>admin</username><password>admin@123</password></user>" .
    "<user><username>guest</username><password>guest@123</password></user>" .
    "</users>";

//Input example : 
$inputUsername = "admin' or '1'='1' or '";
$inputPassword = "randomPassword";

$doc = new DOMDocument();
$doc->loadXML($xmlInput);

$xpath = new DOMXPath($doc);

$query = "//user[username/text()='$inputUsername' and password/text()='$inputPassword']";
$nodes = $xpath->query($query);

echo ($nodes->length > 0) ? "Authenticated" : "Authentication Failed";
?>
```

