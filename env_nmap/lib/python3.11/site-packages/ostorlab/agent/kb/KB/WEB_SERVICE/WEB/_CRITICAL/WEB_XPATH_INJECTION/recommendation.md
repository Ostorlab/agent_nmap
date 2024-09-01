To mitigate XPath Injection vulnerabilities, it is important to: 

* Use parameterized queries or prepared statements, which separate the user input from the query logic.
* Properly validate and sanitize user input before using it in XPath queries. 


=== "Java"
  ```java
  import org.dom4j.Document;
  import org.dom4j.XPath;
  import org.dom4j.io.SAXReader;
  import org.jaxen.SimpleVariableContext;
  
  import java.io.File;
  
  public class Main {
      public static void main(String[] args) {
          try {
              // Assuming 'user' and 'pass' variables are already defined
              String user = "username";
              String pass = "password";
  
              // Load your XML document
              File inputFile = new File("input.xml");
              SAXReader reader = new SAXReader();
              Document document = reader.read(inputFile);
  
              // Create a SimpleVariableContext and set variables
              SimpleVariableContext svc = new SimpleVariableContext();
              svc.setVariableValue("user", user);
              svc.setVariableValue("pass", pass);
  
              // Define your XPath expression
              String xpathString = "/users/user[@name=$user and @pass=$pass]";
  
              // Create XPath object and set the variable context
              XPath safeXPath = document.createXPath(xpathString);
              safeXPath.setVariableContext(svc);
  
              // Evaluate XPath expression and check if any node is selected
              boolean isExist = safeXPath.selectSingleNode(document) != null;
              System.out.println(isExist);
          } catch (Exception e) {
              e.printStackTrace();
          }
      }
  }
  ```