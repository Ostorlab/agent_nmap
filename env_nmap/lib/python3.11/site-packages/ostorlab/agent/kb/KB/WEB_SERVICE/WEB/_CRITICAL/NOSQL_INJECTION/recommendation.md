To prevent NoSQL injection attacks, consider the following  measures:

- __Safe Query Construction__: Construct queries using the database's specific methods or query builders provided by the API. Avoid directly concatenating user inputs into queries. Instead, use the appropriate mechanisms provided by the database API for safe query construction.

- __Input Validation and Sanitization__: Implement robust input validation to ensure that user-supplied data meets expected formats. Use sanitization techniques like whitelisting acceptable characters to prevent unwanted input.

- __Use whitelist of accepted keys__: To prevent operator injection, use a whitelist of accepted keys to prevent injection of query operators like `$where`, `$in`, `$ne`.

### Examples

=== "Java"

  ```java
    import com.mongodb.*;
    import java.util.regex.Pattern;
    
    public class SecureNoSQLInjection {
        public static void main(String[] args) {
            String username = sanitizeInput(args[0]);
            String password = sanitizeInput(args[1]);
    
            MongoClientURI uri = new MongoClientURI("mongodb://localhost:27017");
            MongoClient mongoClient = new MongoClient(uri);
    
            DB database = mongoClient.getDB("test");
            DBCollection collection = database.getCollection("users");
    
            BasicDBObject query = new BasicDBObject();
            query.put("username", username);
            query.put("password", password);
    
            DBCursor cursor = collection.find(query);
    
            while (cursor.hasNext()) {
                System.out.println(cursor.next());
            }
        }
    
        // Function to sanitize input (escape special characters)
        private static String sanitizeInput(String input) {
            return Pattern.quote(input); // Escapes special characters in the input string
        }
    }

  ```


=== "Javascript"

  ```javascript
    const MongoClient = require('mongodb').MongoClient;
    const express = require('express');
    const mongoSanitize = require('mongo-sanitize');
    const app = express();
    
    // Middleware to parse incoming JSON requests
    app.use(express.json());
    
    app.post('/login', async (req, res) => {
        const username = mongoSanitize.sanitize(req.body.username);
        const password = mongoSanitize.sanitize(req.body.password);
    
        const uri = 'mongodb://localhost:27017';
        const client = new MongoClient(uri);
    
        try {
            await client.connect();
            const database = client.db('test');
            const usersCollection = database.collection('users');
    
            // Secure query using parameterization to prevent NoSQL Injection
            const user = await usersCollection.findOne({ username, password }); // Secure code with input sanitization
    
            res.json({ success: user !== null });
        } finally {
            await client.close();
        }
    });
    
    app.listen(3000, () => {
        console.log('Server started on port 3000');
    });
  ```



=== "Php"

  ```php
    <?php
    $username = $_POST['username'] ?? null;
    $password = $_POST['password'] ?? null;
    
    $sanitizedUsername = filter_var($username, FILTER_SANITIZE_STRING);
    
    $manager = new MongoDB\Driver\Manager('mongodb://localhost:27017');
    
    // Using prepared statements for the query
    $query = new MongoDB\Driver\Query([
        'username' => $sanitizedUsername,
        'password' => ['$eq' => $password] // Use an exact match for the password
    ]);
    
    try {
        $cursor = $manager->executeQuery('test.users', $query);
    
        foreach ($cursor as $document) {
            var_dump($document);
        }
    } catch (MongoDB\Driver\Exception\Exception $e) {
        echo "Exception: ", $e->getMessage();
    }
    ?>
  ```