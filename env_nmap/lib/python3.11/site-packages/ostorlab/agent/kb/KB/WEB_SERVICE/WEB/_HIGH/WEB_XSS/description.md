Cross-site-scripting (XSS) vulnerabilities occur when unsanitized user-controlled input is served to the user.

XSS vulnerabilities bypass same-Origin-Policy, which is a core principle of web security. SOP ensures that a page
from `http://evil.com` can't access the content of a page from `http://bank.com`.

XSS is commonly separated into three families

* **Reflected:** the user-controlled input is directly reflected in the page response
* **Stored:** the user-controlled input is stored on the server side, for instance, in a database, and is later returned
  to user
* **DOM-based:** the user-controlled input is injected on the client-side to the DOM, triggering the injection of
  malicious JavaScript

XSS vulnerabilities allow an attacker to perform a variety of malicious actions, like exfiltration of personal data,
including user session or account information; perform actions on behalf of the user.


### Examples

=== "Java"
  ```java
  import javax.servlet.http.*;
  import java.io.*;
  
  public class VulnerableXSS extends HttpServlet {
      protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
          String userInput = request.getParameter("input");
          String page = "<html><body><h2>User Input: " + userInput + "</h2></body></html>";
  
          PrintWriter out = response.getWriter();
          out.println(page);
      }
  }

  ```

=== "JavaScript"
  ```javascript
  const express = require('express');
  const app = express();
  
  app.get('/vulnerable', (req, res) => {
    const userInput = req.query.input;
    res.send(`<html><body><h2>User Input: ${userInput}</h2></body></html>`);
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
        <title>XSS Vulnerability</title>
    </head>
    <body>
        <h1>Welcome to the Vulnerable Page</h1>
        <p>Search for a product:</p>
        <form action="/search">
            <input type="text" name="query" placeholder="Enter product name">
            <input type="submit" value="Search">
        </form>
        <p>Search results:</p>
        <div id="results">
            <!-- Display search results here -->
            <?php
                // Vulnerable code - directly echoing user input without sanitization
                $query = $_GET['query'];
                echo "<p>You searched for: " . $query . "</p>";
            ?>
        </div>
    </body>
    </html>
  ```