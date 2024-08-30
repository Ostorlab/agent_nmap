To ensure a safe validation of the hostname, consider the implementations below.

1. Implement Regular Expression (Regex) Validation: Instead of using simple methods like `startsWith` or `endsWith`, opt for regular expressions to perform thorough hostname validation. Regex patterns can allow for precise matching criteria.

2. Consider Standardized Validation Libraries: Utilize established libraries or frameworks that offer robust hostname validation functionalities. These libraries are often well-maintained and regularly updated to address potential security flaws.

3. Implement Whitelisting: If you have a limited number of whitelisted hosts, consider implementing a whitelist approach where only known and trusted hostnames are accepted by the application. 

=== "Java"
  ```java
  import java.util.regex.*;

  public class SubdomainValidator {
      public static void main(String[] args) {
          String userInput = "sub.example.com"; // replace this with user input
          
          // Regular expression pattern to match subdomains of example.com
          String pattern = "^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\.)+example\\.com$";
          
          // Create a Pattern object
          Pattern r = Pattern.compile(pattern);
          
          // Create Matcher object
          Matcher m = r.matcher(userInput);
          
          // Check if input matches the pattern
          if (m.find()) {
              System.out.println("Valid subdomain of example.com");
          } else {
              System.out.println("Invalid subdomain of example.com");
          }
      }
  }
  ```

=== "Swift"
  ```swift
  import Foundation
  
  func isValidSubdomain(_ userInput: String) -> Bool {
      let pattern = #"^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+example\.com$"# // Regular expression pattern
      let regex = try! NSRegularExpression(pattern: pattern)
      let range = NSRange(location: 0, length: userInput.utf16.count)
      return regex.firstMatch(in: userInput, options: [], range: range) != nil
  }
  
  let userInput = "sub.example.com" // replace this with user input
  if isValidSubdomain(userInput) {
      print("Valid subdomain of example.com")
  } else {
      print("Invalid subdomain of example.com")
  }
  ```

=== "Flutter"
  ```dart
  import 'package:flutter/material.dart';
  
  bool isValidSubdomain(String userInput) {
    RegExp regex = RegExp(r'^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+example\.com$');
    return regex.hasMatch(userInput);
  }
  
  void main() {
    String userInput = "sub.example.com"; // replace this with user input
    if (isValidSubdomain(userInput)) {
      print("Valid subdomain of example.com");
    } else {
      print("Invalid subdomain of example.com");
    }
  }
  ```