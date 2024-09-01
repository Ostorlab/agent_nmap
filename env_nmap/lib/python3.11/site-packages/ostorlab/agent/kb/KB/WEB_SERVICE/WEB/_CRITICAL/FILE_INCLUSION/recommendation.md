To address File Inclusion vulnerabilities, consider the following recommendations:

- **Avoid Dynamic File Inclusion from user input:** unless necessary, avoid calling `include()`, `require()` or similar functions with user controlled input.
- **Input Whitelisting:** Use whitelists to only allow known and expected input values.
- **Input Validation and Sanitization:** Sanitize user input from special characters that may allow for path traversal like `../`
- **Use File Mapping Array**: Create an array that assigns unique indexes to allowed files. Each index corresponds to a specific file within your application.


=== "PHP"
  ```php
  <?php
  
  // Get the requested page from the query string
  $page = isset($_GET['page']) ? $_GET['page'] : 'home';
  
  // Define a whitelist of allowed pages
  $allowed_pages = ['home', 'about', 'contact'];
  
  // Check if the requested page is in the whitelist
  if (in_array($page, $allowed_pages)) {
  // Include the valid page
  include($page . '.php');
  } else {
  // Redirect to a default page or display an error message
  include('error.php');
  }
  
  ?>
  ```

=== "JSP"
  ```jsp
  <%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
  <%@ page import="java.util.List" %>
  
  <%
  // Get the requested page from the query string
  String page = request.getParameter("page");
  
  // Define a whitelist of allowed pages
  List<String> allowedPages = List.of("home", "about", "contact");
  
  // Check if the requested page is in the whitelist
  if (allowedPages.contains(page)) {
      // Include the valid page
      %><jsp:include page="<%= page %>.jsp" /><%
  } else {
      // Redirect to a default page or display an error message
      response.sendRedirect("error.jsp");
  }
  %>
  ```

=== "SSI"
  ```ssi
  <!DOCTYPE html>
  <html>
  <head>
  <title>Test file</title>
  </head>
  <body>
  <!--#if expr='"$USER_LANGUAGE" =~ /^(en|fr|es)$/ -->
     <!--#include file="/path/to/allowed_languages/$USER_LANGUAGE"-->
  <!--#else -->
     <p>Invalid language selection.</p>
  <!--#endif -->
  </body>
  </html>
  ```