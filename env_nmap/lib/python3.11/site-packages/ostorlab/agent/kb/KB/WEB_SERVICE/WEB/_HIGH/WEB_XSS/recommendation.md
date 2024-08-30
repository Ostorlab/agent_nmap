In general, cases, preventing XSS vulnerabilities requires 2-step protection:

* **Input validation:** user-controlled input should be validated to forbid all unauthorized characters, phone number
  For instance, only numbers; names should only contain alphabetical characters, etc.
* **Output encoding:** all input shown to the user is encoded correctly using proven standard API. Use of a safe
  template engines with native support for output encoding and secure defaults are highly recommended.

### Examples

=== "Java"
  ```java
  import org.apache.commons.text.StringEscapeUtils;
  import javax.servlet.http.*;
  import java.io.*;
  
  public class SecureXSSWithLibrary extends HttpServlet {
      protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
          String userInput = request.getParameter("input");
          String sanitizedInput = StringEscapeUtils.escapeHtml4(userInput);
          String page = "<html><body><h2>User Input: " + sanitizedInput + "</h2></body></html>";
  
          PrintWriter out = response.getWriter();
          out.println(page);
      }
  }
  ```
=== "JavaScript"
  ```javascript
  const express = require('express');
  const app = express();
  const { escape } = require('html-escaper'); // Using 'html-escaper' library
  
  app.get('/secure', (req, res) => {
    const userInput = req.query.input;
    const sanitizedInput = escape(userInput);
    res.send(`<html><body><h2>User Input: ${sanitizedInput}</h2></body></html>`);
  });
  
  app.listen(3000, () => {
    console.log('Server started on port 3000');
  });
  ```


=== "PHP"
  ```php
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Page</title>
    </head>
    <body>
        <h1>Welcome to the Secure Page</h1>
        <p>Search for a product:</p>
        <form action="/search">
            <input type="text" name="query" placeholder="Enter product name">
            <input type="submit" value="Search">
        </form>
        <p>Search results:</p>
        <div id="results">
            <!-- Display sanitized search results here -->
            <?php
                // Sanitizing user input before displaying
                $query = $_GET['query'];
                echo "<p>You searched for: " . htmlspecialchars($query, ENT_QUOTES, 'UTF-8') . "</p>";
            ?>
        </div>
    </body>
    </html>
  ```
