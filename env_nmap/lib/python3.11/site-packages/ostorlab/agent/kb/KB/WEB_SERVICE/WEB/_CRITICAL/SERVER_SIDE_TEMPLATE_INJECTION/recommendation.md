- Avoid creating templates from user input whenever possible
- Consider using a simple logic-less template engine such as Mustache 
- Render templates in a sandbox environment where risky modules and features are disabled.
- Sanitize user input before passing it into the template

### Examples

=== "Ruby"
  ```ruby
  # app.rb
  require 'sinatra'
  require 'mustache'
  
  class ExampleTemplate < Mustache
    def initialize(name)
      @name = name
    end
  
    def greeting
      "Hello, #{@name}!"
    end
  end
  
  get '/greet/:name' do
    name = params['name']
    template = ExampleTemplate.new(name)
    erb template.render
  end
  ```

=== "PHP"
  ```php
  <!-- index.php -->
  <?php
  require 'Mustache/Autoloader.php';
  Mustache_Autoloader::register();
  
  $template = new Mustache_Engine;
  
  $name = $_GET['name'] ?? 'World';
  $data = ['name' => $name];
  echo $template->render('Hello, {{name}}!', $data);
  ?>
  ```

=== "Python"
  ```python
  from flask import Flask, render_template
  from flask import request
  import pystache
  
  app = Flask(__name__)
  
  # Define a simple Mustache template
  template = """
  <html>
  <head>
      <title>Greeting Page</title>
  </head>
  <body>
      <h1>Hello, {{name}}!</h1>
  </body>
  </html>
  """
  
  # Create a Mustache renderer
  mustache_renderer = pystache.Renderer()
  
  @app.route('/')
  def greet_user():
      # Get the 'name' query parameter from the URL
      user_name = request.args.get('name', 'Guest')
  
      # Render the template with the user's name
      rendered_template = mustache_renderer.render(template, {'name': user_name})
  
      # Return the rendered HTML
      return rendered_template
  
  if __name__ == '__main__':
      app.run(debug=True)
  ```