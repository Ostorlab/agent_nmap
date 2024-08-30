To prevent SQL injection attacks, consider the following  measures:

- __Parameterized Queries__: Use parameterized queries or prepared statements to execute SQL queries. Parameterization allows for separating SQL code from user input, preventing injection attacks.


- __Input Sanitization__: Validate and sanitize user inputs before using them in SQL queries. Implement strict input validation by allowing only expected characters and formats.


- __Least Privilege Principle__: Use the principle of least privilege for database users. Assign minimal necessary permissions to limit the impact of successful injection attacks.


- __ORMs and Libraries__: Utilize Object-Relational Mapping (ORM) libraries or frameworks that handle SQL queries dynamically. These frameworks often provide built-in protections against injection attacks.


### Examples

=== "Java"
  ```java
    import java.sql.Connection;
    import java.sql.DriverManager;
    import java.sql.PreparedStatement;
    import java.sql.ResultSet;
    import java.sql.SQLException;
    
    public class ParametrizedQueryExample {
        public static void main(String[] args) {
            String username = "userInput"; // User input
            String password = "userInput"; // User input
    
            try (Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "username", "password")) {
                String query = "SELECT * FROM users WHERE username = ? AND password = ?";
                PreparedStatement statement = connection.prepareStatement(query);
    
                statement.setString(1, username);
                statement.setString(2, password);
    
                ResultSet resultSet = statement.executeQuery();
                while (resultSet.next()) {
                    // Process the results
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
  ```

=== "JavaScript"
  ```javascript
    const mysql = require('mysql2/promise');
    
    async function fetchUser(username, password) {
        const connection = await mysql.createConnection({
            host: 'localhost',
            user: 'username',
            password: 'password',
            database: 'db'
        });
    
        const [rows] = await connection.execute('SELECT * FROM users WHERE username = ? AND password = ?', [username, password]);
        connection.end();
        return rows;
    }
    
    // Usage
    fetchUser('userInput', 'userInput')
        .then(rows => {
            // Process the results
        })
        .catch(err => {
            console.error(err);
        });
  ```

=== "PHP"
  ```php
    <?php
        $username = $_POST['username'];
        $password = $_POST['password'];
        
        $db = new mysqli('localhost', 'username', 'password', 'dbname');
        
        if ($stmt = $db->prepare("SELECT * FROM users WHERE username = ? AND password = ?")) {
            $stmt->bind_param('ss', $username, $password);
            $stmt->execute();
        
            $result = $stmt->get_result();
        
            while ($row = $result->fetch_assoc()) {
                // Process the results
            }
        
            $stmt->close();
        }
        
        $db->close();
    ?>
  ```