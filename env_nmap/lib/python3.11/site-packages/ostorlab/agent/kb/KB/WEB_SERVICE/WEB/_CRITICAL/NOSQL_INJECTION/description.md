NoSQL injection is a security vulnerability that occurs when attackers exploit weaknesses in applications using NoSQL databases. It involves injecting malicious or unexpected data into input fields, enabling attackers to manipulate queries and access unauthorized information.

Similar to SQL injection attacks against SQL databases, NoSQL injection targets applications utilizing NoSQL databases like MongoDB, Cassandra, or others. Attackers craft input, such as special characters or payloads, to manipulate NoSQL database queries executed by the application.

By injecting the crafted input, attackers aim to alter the logic of database queries, bypass authentication, or retrieve sensitive information stored in the database. NoSQL injection attacks can lead to unauthorized data access, data modification, or even the complete compromise of the database, compromising the confidentiality, integrity, and availability of the application and its data.




### Examples

=== "Java"
  ```java
    import com.mongodb.*;
    import org.springframework.web.bind.annotation.*;
    
    @RestController
    @RequestMapping("/login")
    public class NoSQLInjectionController {
    
        @PostMapping
        public void login(@RequestParam String userName, @RequestParam String password) {
            MongoClientURI uri = new MongoClientURI("mongodb://localhost:27017");
            MongoClient mongoClient = new MongoClient(uri);
    
            try {
                DB database = mongoClient.getDB("test");
                DBCollection collection = database.getCollection("users");
    
                BasicDBObject query = new BasicDBObject();
                query.put("$where", "this.sharedWith == \"" + userName + "\" && this.password == \"" + password + "\"");
    
                DBCursor cursor = collection.find(query);
    
                while (cursor.hasNext()) {
                    System.out.println(cursor.next());
                }
            } finally {
                mongoClient.close();
            }
        }
    }
  ```

=== "Javascript"

  ```javascript
    const MongoClient = require('mongodb').MongoClient;
    const express = require('express');
    const app = express();
    
    app.post('/login', async (req, res) => {
        const username = req.body.username;
        const password = req.body.password;
    
        const uri = 'mongodb://localhost:27017';
        const client = new MongoClient(uri);
    
        try {
            await client.connect();
            const database = client.db('test');
            const usersCollection = database.collection('users');
    
            // Vulnerable query susceptible to NoSQL Injection
            query = { $where: `this.username == '${username}' && this.password == '${password}'` }
            const user = await usersCollection.find(query);
    
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
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $manager = new MongoDB\Driver\Manager('mongodb://localhost:27017');
    
    $query = [ "username" => $username, 'password' => $password ];
    $testquery = new MongoDB\Driver\Query($query, []);
    
    $cursor = $manager->executeQuery('test.users', $testquery);
    
    foreach ($cursor as $document) {
        var_dump($document);
    }
    ?>
  ```

