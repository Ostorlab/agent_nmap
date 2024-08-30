Mobile SQL Injection is a vulnerability that allows attackers to inject malicious SQL statements into mobile applications, potentially gaining unauthorized access to sensitive data or manipulating the database.

### Examples

#### Kotlin

```kotlin
kotlin
import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.sql.ResultSet

fun main() {
    val input = readLine() ?: ""
    val connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydatabase", "username", "password")
    val statement = connection.prepareStatement("SELECT * FROM users WHERE username = ?")
    statement.setString(1, input)
    val resultSet = statement.executeQuery()
    
    while (resultSet.next()) {
        val username = resultSet.getString("username")
        val password = resultSet.getString("password")
        println("Username: $username, Password: $password")
    }
    
    resultSet.close()
    statement.close()
    connection.close()
}
```
