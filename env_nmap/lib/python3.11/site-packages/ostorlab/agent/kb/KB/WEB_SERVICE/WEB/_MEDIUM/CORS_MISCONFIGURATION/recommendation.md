To mitigate `CORS` misconfiguration vulnerabilities, it is important to follow best practices. This includes properly configuring the `Access-Control-Allow-Origin` header to only allow trusted origins, rather than using the wildcard (`*`) value. Additionally, it is crucial to implement proper authentication and authorization mechanisms to ensure that only authorized users can access sensitive resources. Regularly monitoring and auditing `CORS` configurations can help identify and address any potential misconfigurations or vulnerabilities.

Below are examples of secure settings of CORS:

=== "Django"
   ```Python
       CORS_ALLOWED_ORIGINS = [
       "https://cross-origin-website.com",
       "https://sub.cross-origin-website.com",
       ]
       CORS_ALLOW_METHODS = [
           "DELETE",
           "GET",
           "OPTIONS",
           "PATCH",
           "POST",
           "PUT",
       ]
   ```

=== "NodeJs"
   ```javascript
       const express = require('express');
       const cors = require('cors');
       const app = express();
   
           const ingredients = [];
   
       app.use(cors({
           origin: 'https://cross-origin-website.com'
       }));
   
       app.get('/ingredients', (req, res) =>{
           res.send(ingredients);
       });
       app.listen(6069);
   ```
   

=== "Sprint boot"
   ```java
       import org.springframework.boot.autoconfigure.SpringBootApplication
       import org.springframework.boot.runApplication
       import org.springframework.web.bind.annotation.CrossOrigin
       import org.springframework.web.bind.annotation.GetMapping
       import org.springframework.web.bind.annotation.PathVariable
       import org.springframework.web.bind.annotation.RestController
       
       @SpringBootApplication
       class DemoApplication
       
       fun main(args: Array<String>) {
           runApplication<DemoApplication>(*args)
       }
       
       @RestController
       class UserController {
       
           @CrossOrigin(origins = ["http://localhost:8080"]) // Replace with your allowed origin(s)
           @GetMapping("/users/{id}")
           fun getUser(@PathVariable id: String): String {
               // Fetch user data from the database based on the provided id
               return "User with id $id"
           }
       }
   ```
   