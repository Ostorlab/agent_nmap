To mitigate the risk of path traversal, consider the following recommendations:

- __Avoid direct concatenation__: Avoid concatenating user input directly when constructing filesystem paths.
- __User input sanitization__: Sanitize user input before using it in filesystem path construction, character sequences like `../` should be stripped and the path should be normalized.
- __Use Robust Path Parsers__: Use well-established and secure path parsing packages, some packages might be inherently vulnerable to path traversal .
- __Check path containment__: After validating the supplied input, append the input to the base directory and use a platform filesystem API to canonicalize the path. Verify that the canonicalized path is contained within the base directory.


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
  public class MitigatedPathTraversalExample {
  
      public static void main(String[] args) {
    SpringApplication.run(MitigatedPathTraversalExample.class, args);
      }
  }
  
  @RestController
  class MitigatedFileController {
  
      @PostMapping("/processFile")
      public String processFile(@RequestBody String userInput) {
    try {
        // Mitigated: Validate user input to prevent path traversal
        if (!isValidInput(userInput)) {
      return "Invalid file path.";
        }
  
        // Safe file inclusion with proper input validation
        String filePath = "/var/www/data/" + userInput;
  
        // Process the file content
        return processFileContent(filePath);
    } catch (Exception e) {
        return "Error processing file content: " + e.getMessage();
    }
      }
  
      private boolean isValidInput(String userInput) {
    // Mitigated: Implement proper input validation (e.g., regex)
    // In a real-world scenario, use a more robust validation mechanism.
    return userInput.matches("[a-zA-Z0-9_-]+\\.pdf");
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
    // Mitigated: Validate user input to prevent path traversal
    if (!isValidInput(req.body)) {
        res.status(400).send('Invalid file path.');
        return;
    }
  
    // Safe file inclusion with proper input validation
    const filePath = '/var/www/data/' + req.body;
  
    // Process the file content
    const content = processFileContent(filePath);
    res.send(content);
      } catch (error) {
    res.status(500).send('Error processing file content: ' + error.message);
      }
  });
  
  function isValidInput(userInput) {
      // Mitigated: Implement proper input validation (e.g., regex)
      // In a real-world scenario, use a more robust validation mechanism.
      return userInput.match(/^[a-zA-Z0-9_-]+\.pdf$/);
  }
  
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
  
  // Mitigated: Validate user input to prevent path traversal
  $userInput = $_POST['userInput'];
  if (!isValidInput($userInput)) {
      http_response_code(400);
      echo 'Invalid file path.';
      exit;
  }
  
  // Safe file inclusion with proper input validation
  $filePath = '/var/www/data/' . $userInput;
  
  // Process the file content
  echo processFileContent($filePath);
  
  function isValidInput($userInput) {
      // Mitigated: Implement proper input validation (e.g., regex)
      // In a real-world scenario, use a more robust validation mechanism.
      return preg_match('/^[a-zA-Z0-9_-]+\.pdf$/', $userInput);
  }
  
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