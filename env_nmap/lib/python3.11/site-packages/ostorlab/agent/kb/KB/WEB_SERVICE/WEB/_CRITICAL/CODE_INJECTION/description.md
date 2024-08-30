Code Injection refers to a category of attack methods involving the insertion of code that the application subsequently evaluates. This form of attack takes advantage of poor handling of untrusted data. Such vulnerabilities often arise from insufficient validation of input/output user supplied data.

Code Injection sets itself apart from Command Injection by the fact that an attacker's capabilities are constrained solely by the functionalities inherent in the target programming language. For instance, if an attacker successfully injects PHP code into an application and executes it, their actions are restricted by the capabilities of PHP. On the other hand, Command Injection involves exploiting pre-existing code to execute system commands.


=== "Ruby"
  ```ruby
  print "Enter math equation: "
  user_input = gets.chomp
  
  begin
    result = eval(user_input)
    puts "Result: #{result}"
  rescue StandardError => e
    puts "Error: #{e.message}"
  end
  ```

=== "PHP"
  ```php
  <?php
  $userInput = $_POST['expression']; 
  
  $result = null;
  try {
      eval("\$result = $userInput;");
  } catch (ParseError $e) {
      echo "Error: Invalid Expression";
  }
  
  echo "Result: " . $result;
  ?>
  ```


=== "Python"
  ```python
  try:
      user_input = input("Enter a math expression: ")
      result = eval(user_input)
      print("Result:", result)
  except Exception as e:
      print("Error:", e)
  ```

