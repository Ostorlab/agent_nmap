- __Avoid direct concatenation__: Avoid concatenating user input directly in XML documents.
- __User input sanitization__: Sanitize user input before inserting it into XML documents.
- __Robust XML Parsers__: Use well-established and secure XML parsers that adhere to the XML specifications. Be cautious of custom or outdated parsers that may have vulnerabilities.
- __Disable dangerous XML features__: if not needed, disable external entity expansion to reduce the attack surface and mitigate the risk of XXE vulnerabilities.


=== "Java"
  ```java
  import org.w3c.dom.Document;
  import org.w3c.dom.Element;
  import javax.xml.parsers.DocumentBuilder;
  import javax.xml.parsers.DocumentBuilderFactory;
  import java.io.StringReader;
  
  public class MitigatedXMLInjectionExample {
  
      public static void main(String[] args) {
    // Simulated user input (this should come from a user or external source)
    String userInput = "<maliciousTag>Payload</maliciousTag>";
  
    // Mitigated XML construction with proper input validation
    String sanitizedInput = sanitizeUserInput(userInput);
    String xmlData = "<data>" + sanitizedInput + "</data>";
  
    // Process the XML data (mitigated code)
    processXmlData(xmlData);
      }
  
      public static String sanitizeUserInput(String input) {
    // Perform proper input validation and sanitization
    // For example, you can use a library or a regex to remove invalid characters
    return input.replaceAll("[&<>\"]", "");
      }
  
      public static void processXmlData(String xmlData) {
    try {
        // Parse the XML data
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new org.xml.sax.InputSource(new StringReader(xmlData)));
  
        // Extract information from the XML (mitigated code)
        Element root = document.getDocumentElement();
        String content = root.getTextContent();
        System.out.println("Processed XML data: " + content);
    } catch (Exception e) {
        System.err.println("Error processing XML data: " + e.getMessage());
    }
      }
  }
  ```

=== "JavaScript"
  ```javascript
  const userInput = '<maliciousTag>Payload</maliciousTag>';
  
  // Mitigated XML construction with proper input validation
  const sanitizedInput = sanitizeUserInput(userInput);
  const xmlData = '<data>' + sanitizedInput + '</data>';
  
  // Process the XML data (mitigated code)
  processXmlData(xmlData);
  
  function sanitizeUserInput(input) {
      // Perform proper input validation and sanitization
      // For example, you can use a library like DOMPurify for HTML/XML sanitization
      // Here, we are using a simple approach to remove invalid characters
      return input.replace(/[&<>"']/g, '');
  }
  
  function processXmlData(xmlData) {
      try {
    // Parse the XML data
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlData, 'text/xml');
  
    // Extract information from the XML (mitigated code)
    const content = xmlDoc.getElementsByTagName('data')[0].textContent;
    console.log('Processed XML data: ' + content);
      } catch (error) {
    console.error('Error processing XML data: ' + error.message);
      }
  }
  ```

=== "PHP"
  ```php
  <?php
  $userInput = '<maliciousTag>Payload</maliciousTag>';
  
  // Mitigated XML construction with proper input validation
  $sanitizedInput = sanitizeUserInput($userInput);
  $xmlData = '<data>' . $sanitizedInput . '</data>';
  
  // Process the XML data (mitigated code)
  processXmlData($xmlData);
  
  function sanitizeUserInput($input) {
      // Perform proper input validation and sanitization
      // For example, you can use functions like htmlspecialchars to sanitize XML content
      return htmlspecialchars($input, ENT_XML1, 'UTF-8');
  }
  
  function processXmlData($xmlData) {
      try {
    // Create a new DOMDocument
    $doc = new DOMDocument();
  
    // Load the XML data
    $doc->loadXML($xmlData);
  
    // Extract information from the XML (mitigated code)
    $content = $doc->getElementsByTagName('data')->item(0)->textContent;
    echo 'Processed XML data: ' . $content . PHP_EOL;
      } catch (Exception $e) {
    echo 'Error processing XML data: ' . $e->getMessage() . PHP_EOL;
      }
  }
  ?>
  ```