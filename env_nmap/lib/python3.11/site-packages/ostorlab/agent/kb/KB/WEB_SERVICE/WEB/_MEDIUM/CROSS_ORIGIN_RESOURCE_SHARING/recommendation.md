To mitigate the security risks associated with Cross-Origin Resource Sharing (CORS), you can implement server-side controls to restrict access to resources based on the origin of the requesting client.

=== "Express"
  ```javascript
  const express = require('express');
  const cors = require('cors');
  const app = express();
  
  // Define a whitelist of allowed origins
  const whitelist = ['http://example1.com', 'http://example2.com'];
  
  // Configure CORS options
  const corsOptions = {
    origin: function (origin, callback) {
      if (whitelist.indexOf(origin) !== -1 || !origin) {
        callback(null, true); // Allow request
      } else {
        callback(new Error('Not allowed by CORS')); // Deny request
      }
    }
  };
  
  // Apply CORS middleware with configured options
  app.use(cors(corsOptions));
  
  // Define routes
  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  
  // Start the server
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
  ```

=== "Flask"
  ```python
  from flask import Flask, jsonify, request
  from flask_cors import CORS
  
  app = Flask(__name__)
  
  # Define a list of allowed origins
  allowed_origins = [
      'http://example.com',
      'https://example.com',
      # Add more origins as needed
  ]  

  # Initialize CORS with the whitelist
  CORS(app, origins=allowed_origins) 
  
  # Define routes
  @app.route('/')
  def hello_world():
      return jsonify(message='Hello World!')
  
  if __name__ == '__main__':
      app.run(debug=True)
  ```


=== "PHP"
  ```php
  <?php
  
  // Enable CORS
  header('Access-Control-Allow-Origin: http://example.com');
  header('Access-Control-Allow-Methods: GET, POST');
  header('Access-Control-Allow-Headers: Content-Type');
  
  // Handle CORS pre-flight OPTIONS request
  if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
      header('Access-Control-Allow-Methods: GET, POST');
      header('Access-Control-Allow-Headers: Content-Type');
      exit;
  }
  
  // Define your API logic
  if ($_SERVER['REQUEST_METHOD'] === 'GET') {
      echo json_encode(array('message' => 'Hello World!'));
  } else {
      http_response_code(405); // Method Not Allowed
  }
  ?>
  ```