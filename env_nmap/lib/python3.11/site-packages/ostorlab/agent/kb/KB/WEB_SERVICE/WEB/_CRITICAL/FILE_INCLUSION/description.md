A file inclusion vulnerability is a type of web vulnerability that usually affects programming languages that rely on a scripting run time. This vulnerability arises when an application constructs a path to executable code using a user controlled argument. This construction allows the attacker to dictate which file gets executed during runtime. 

Unlike a path traversal attack, where unauthorized access to the file system allows read-only file access, a file inclusion vulnerability allows for the inclusion and the execution of code at runtime. Successfully exploiting this vulnerability may allow for remote code execution, unauthorized file access and sensitive information leakage.

File inclusion vulnerabilities can be divided into two major categories:

- Local File Inclusion (LFI): In this scenario, an attacker is limited to local files present on the web server, depending on the programming language and the configuration, it may be possible to escalate this attack into a remote code execution using special schemes like `php://`.
- Remote File Inclusion (RFI): Although not very common in modern web apps, if present, this vulnerability may allow for remote code execution by including malicious.


=== "PHP"
  ```php
  <?php
  
  $page = $_GET['page'];
  include($page . '.php');
  
  ?>
  ```

=== "JSP"
  ```jsp
  <%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
  
  <%
  
  String page = request.getParameter("page");
  include(page + ".jsp");
  
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
  <!--#include file="$USER_LANGUAGE"-->
  </body>
  </html>
  ```

