`CORS` misconfiguration refers to a vulnerability where Cross-Origin Resource Sharing (`CORS`) policies are not properly configured on a web server. This allows unauthorized cross-origin requests to be made, potentially leading to information leakage or unauthorized access to sensitive data.

Below are examples of incorrect CORS configuration on different popular frameworks:

=== "Django"
   ```Python
   CORS_ALLOWED_ORIGIN_REGEXES = [
       r"*",
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
        origin: '*'
    }));

    app.get('/ingredients', (req, res) =>{
        res.send(ingredients);
    });
    app.listen(6069);
  ```

=== "Spring Boot"
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
       
           @CrossOrigin(origins = "*")
           @GetMapping("/users/{id}")
           fun getUser(@PathVariable id: String): String {
               // Fetch user data from the database based on the provided id
               return "User with id $id"
           }
       }
   ```
