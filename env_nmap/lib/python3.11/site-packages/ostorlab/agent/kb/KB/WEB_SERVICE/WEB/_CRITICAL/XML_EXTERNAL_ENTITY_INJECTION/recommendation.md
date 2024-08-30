To mitigate the risk of XML external entities vulnerabilities, it is recommended to:

- Disable resolution of external entities. 
- Disable support for XInclude. 


=== "Java"
  ```java
  //Input example : 
  String xmlInput = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
      "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" +
      "<foo>&xxe;</foo>";
  
  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
  
  // Enable secure processing mode to mitigate common XML security vulnerabilities
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
  
  // Disable external DTDs and stylesheets to prevent potential XXE attacks
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
  
  DocumentBuilder builder = factory.newDocumentBuilder();
  Document doc = builder.parse(new ByteArrayInputStream(xmlInput.getBytes()));
  ```

=== "JavaScript"  
  ```javascript
  const app = require("express")();
  const libxml = require("libxmljs");
  app.post("/path", (req, res) => {
    Element = libxml.parseXml(req.body);
   // Processing the XML element
  });
  ```

=== "PHP"
  ```php
  <?php
  $loadEntities = libxml_disable_entity_loader(true);
  
  $xmlInput = '<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <foo>&xxe;</foo>';
  
  $doc = new DOMDocument();
  $doc->loadXML($xmlInput);
  
  libxml_disable_entity_loader($loadEntities);
  
  echo $doc->saveXML();
  ?>
  ```