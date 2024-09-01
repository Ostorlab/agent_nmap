To mitigate code injection vulnerabilities, here are some possible mitigations:

- __Avoid evaluating user input__: The best way to protect against code injection is to not evaluate user input at all.


- __Input validation and sanitization__: If evaluating user input is necessary, it should be sanitized first to remove special characters that may allow for code execution like parentheses for example.


- __Using a sandbox environment__: One way to mitigate the risk of code injection is by evaluating user input in an isolated and restricted sandbox environment.


- __Least Privilege Principle__: Although not specifically related to code injection, least privilege principle can help reduce the impact of vulnerabilities by reducing the privilege an attacker might obtain if they manage to successfully compromise the system.


=== "Ruby"
  ```ruby
  print "Enter math equation: "
  user_input = gets.chomp
  
  # Sanitize user input
  sanitized_input = user_input.gsub(/[^0-9+\-\/\*]/, '')
  
  begin
  result = eval(sanitized_input)
  puts "Result: #{result}"
  rescue StandardError => e
  puts "Error: #{e.message}"
  end
  ```

=== "PHP"
  ```php
  <?php
  $userInput = $_POST['expression']; 
  
  // Sanitize user input
  $sanitizedInput = preg_replace("/[^0-9+\-\/\*]/", "", $userInput);
  
  $result = null;
  try {
      $result = eval("return $sanitizedInput;");
  } catch (ParseError $e) {
      echo "Error: Invalid Expression";
  }
  
  echo "Result: " . $result;
  ?>
  ```

=== "Python"
  ```python
  import re
  
  try:
      user_input = input("Enter a Python expression: ")
  
      # Sanitize user input
      sanitized_input = re.sub(r'[^0-9+\-*/]', '', user_input)
  
      result = eval(sanitized_input)
      print("Result:", result)
  except Exception as e:
      print("Error:", e)
  ```