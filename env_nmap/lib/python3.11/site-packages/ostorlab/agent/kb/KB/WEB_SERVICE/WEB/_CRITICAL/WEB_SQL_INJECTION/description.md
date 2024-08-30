SQL Injection is a vulnerability where attackers inject malicious SQL queries into input fields, manipulating the behavior of the application's SQL database. By leveraging this vulnerability, attackers can gain unauthorized access to the database, retrieve, modify, or delete sensitive data, or execute administrative operations on the database. SQL Injection typically arises due to improperly sanitized user inputs, allowing attackers to bypass authentication, execute arbitrary SQL commands, and exploit the underlying database.

### Examples

=== "Java"
  ```java
    import java.sql.*;
    
    public class SQLInjectionDemo {
        public static void main(String[] args) {
            try {
                // Vulnerable Java code prone to SQL Injection
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/database", "username", "password");
                Statement stmt = conn.createStatement();
                
                // Vulnerable SQL query without sanitization
                String username = args[0];
                String password = args[1];
                String sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
                ResultSet rs = stmt.executeQuery(sql);
                
                if (rs.next()) {
                    // User authenticated
                } else {
                    // Invalid credentials
                }
                conn.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

  ```

=== "JavaScript"
  ```javascript
    const mysql = require('mysql');
    
    // Vulnerable Node.js code prone to SQL Injection
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'username',
        password: 'password',
        database: 'database'
    });
    
    // Vulnerable SQL query without sanitization
    const username = req.body.username;
    const password = req.body.password;
    const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    
    connection.query(sql, (error, results) => {
        if (error) throw error;
    
        if (results.length > 0) {
            // User authenticated
        } else {
            // Invalid credentials
        }
    });
    
    connection.end();
  ```

=== "PHP"
  ```php
    <?php
    // Vulnerable PHP code prone to SQL Injection
    $conn = new mysqli('localhost', 'username', 'password', 'database');
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    
    // Vulnerable SQL query without sanitization
    $username = $_POST['username'];
    $password = $_POST['password'];
    $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $result = $conn->query($sql);
    if ($result->num_rows > 0) {
        // User authenticated
    } else {
        // Invalid credentials
    }
    $conn->close();
    ?>
  ```