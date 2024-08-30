Path traversal vulnerabilities occur when user input is improperly handled by a web application, allowing an attacker to navigate outside the intended directory structure and access unauthorized files or directories. Exploiting this vulnerability involves manipulating input to include sequences that can traverse the file system like `../`.

The impact of path traversal vulnerabilities can range from disclosing sensitive information to executing arbitrary code, depending on the context in which the vulnerability is exploited.

 
=== "Java"
  ```java
  import org.springframework.boot.SpringApplication;
  import org.springframework.boot.autoconfigure.SpringBootApplication;
  import org.springframework.web.bind.annotation.PostMapping;
  import org.springframework.web.bind.annotation.RequestBody;
  import org.springframework.web.bind.annotation.RestController;
  
  import java.io.BufferedReader;
  import java.io.FileReader;
  
  @SpringBootApplication
  public class PathTraversalExample {
  
      public static void main(String[] args) {
    SpringApplication.run(PathTraversalExample.class, args);
      }
  }
  
  @RestController
  class FileController {
  
      @PostMapping("/processFile")
      public String processFile(@RequestBody String userInput) {
    try {
        // Vulnerable path traversal without proper input validation
        String filePath = "/var/www/data/" + userInput;
  
        // Process the file content (vulnerable code)
        return processFileContent(filePath);
    } catch (Exception e) {
        return "Error processing file content: " + e.getMessage();
    }
      }
  
      private String processFileContent(String filePath) throws Exception {
    // Read the file content
    BufferedReader br = new BufferedReader(new FileReader(filePath));
    StringBuilder content = new StringBuilder();
    String line;
    while ((line = br.readLine()) != null) {
        content.append(line).append("\n");
    }
    br.close();
    return "Processed file content:\n" + content.toString();
      }
  }
  ```

=== "JavaScript"
  ```javascript
  const express = require('express');
  const bodyParser = require('body-parser');
  const fs = require('fs');
  
  const app = express();
  const port = 3000;
  
  app.use(bodyParser.text());
  
  app.post('/processFile', (req, res) => {
      try {
    // Vulnerable path traversal without proper input validation
    const filePath = '/var/www/data/' + req.body;
  
    // Process the file content (vulnerable code)
    const content = processFileContent(filePath);
    res.send(content);
      } catch (error) {
    res.status(500).send('Error processing file content: ' + error.message);
      }
  });
  
  function processFileContent(filePath) {
      // Read the file content
      const content = fs.readFileSync(filePath, 'utf-8');
      return 'Processed file content:\n' + content;
  }
  
  app.listen(port, () => {
      console.log(`Server listening at http://localhost:${port}`);
  });
  ```

=== "PHP"
  ```php
  <?php
  // Save this file as index.php and run it using: php -S localhost:8000
  
  // Get user input from the POST request
  $userInput = $_POST['userInput'];
  
  // Vulnerable path traversal without proper input validation
  $filePath = '/var/www/data/' . $userInput;
  
  // Process the file content (vulnerable code)
  echo processFileContent($filePath);
  
  function processFileContent($filePath) {
      try {
    // Read the file content
    $content = file_get_contents($filePath);
    return 'Processed file content:' . PHP_EOL . $content;
      } catch (Exception $e) {
    return 'Error processing file content: ' . $e->getMessage();
      }
  }
  ?>
  ```

