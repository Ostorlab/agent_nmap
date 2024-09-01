Regular Expression Denial of Service (ReDoS) is a security vulnerability that occurs when user input is utilized to construct a regular expression. In the presence of a carefully crafted regex pattern, the application may expend a substantial amount of resources, potentially resulting in a denial of service.

Some examples of evil patterns include:

- `(a+)+`
- `([a-zA-Z]+)*`
- `(a|aa)+`
- `(a|a?)+`
- `(.*a){x} for x > 10`

And the following code examples are illustrations of incorrect implementations: 

=== "Java"
  ```java
 import java.util.regex.*;

 public class RegexVulnerabilityExample {
   public static void main(String[] args) {
       // Function to read user input, potentially malicious
       String userInput = getUserInput();

       // Constructing a regular expression using user input
       Pattern pattern = Pattern.compile(userInput);

       // Using the regular expression
       Matcher matcher = pattern.matcher("input_string");
       boolean matchFound = matcher.find();

       if (matchFound) {
           System.out.println("Match found!");
       } else {
           System.out.println("No match found!");
       }
   }
  ```


=== "Swift"
  ```swift
 import Foundation
 
 func checkRegex(input: String, regex: String) {
 
     // Constructing a regular expression using user input
     do {
         let regex = try NSRegularExpression(pattern: userInput)
         let range = NSRange(location: 0, length: input.utf16.count)
         let matchRange = regex.rangeOfFirstMatch(in: input, options: [], range: range)
 
         if matchRange.location != NSNotFound {
             print("Match found!")
         } else {
             print("No match found!")
         }
     } catch {
         print("Error: Invalid regular expression")
     }
 }
 
 // Call the function with user input
 checkRegex(input: "input_string",regex: "redos")
  ```


=== "Flutter"
  ```dart
 import 'package:flutter/material.dart';
 import 'package:flutter/services.dart';
 
 void main() {
   runApp(MyApp());
 }
 
 class MyApp extends StatelessWidget {
   @override
   Widget build(BuildContext context) {
     return MaterialApp(
       home: Scaffold(
         appBar: AppBar(
           title: Text('Regex Vulnerability Example'),
         ),
         body: Center(
           child: ElevatedButton(
             onPressed: () {
               // Function to read user input, potentially malicious
               String userInput = getUserInput();
 
               // Constructing a regular expression using user input
               RegExp regex = RegExp(userInput);
 
               // Using the regular expression
               String inputString = "input_string";
               bool matchFound = regex.hasMatch(inputString);
 
               if (matchFound) {
                 print("Match found!");
               } else {
                 print("No match found!");
               }
             },
             child: Text('Test Regex'),
           ),
         ),
       ),
     );
   }
  ```