SSTI, or Server-Side Template Injection, is a security vulnerability that occurs when an attacker can inject malicious code into a template engine. Template engines are commonly used in web applications to generate dynamic content, and SSTI occurs when user input is not properly validated or sanitized before being included in a template.


=== "Ruby"
  ```ruby
  # Assume user_input contains user-controlled data
  user_input = params[:input]
  
  # Unsafe usage of ERB
  template = ERB.new("<%= #{user_input} %>")
  result = template.result(binding)
  
  # Output the result
  puts result
  ```

=== "PHP"
  ```php
  // Vulnerable PHP code using Twig
  $name = $_GET['name'];
  echo $twig->render('greet.twig', ['name' => $name]);
  ```

=== "Python"
  ```python
  # Vulnerable Python code using Jinja2
  from flask import Flask, render_template, request
  
  app = Flask(__name__)
  
  @app.route('/greet')
  def greet():
      # Injecting user input directly into the template
      username = request.args.get('username')
      return render_template('greet.html', username=username)
  ```

