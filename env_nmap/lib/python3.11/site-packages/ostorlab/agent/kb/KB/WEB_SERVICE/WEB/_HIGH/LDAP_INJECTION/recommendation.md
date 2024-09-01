To mitigate the risk of LDAP injection, consider the following recommendations:

- __Parameterized Queries:__ Use parameterized queries instead of direct concatenation to construct LDAP queries.

- __Input Validation / Sanitization__: Implement input validation to ensure that user input adheres to expected formats and does not contain special characters that might alter LDAP queries, also sanitize user input using methods such as `LdapFilterEncode`

- __Use Frameworks that Automatically Protect from LDAP Injection:__ Utilize well-established and secure LDAP query APIs or libraries that automatically encode user input when building LDAP queries.

- __Enabling Bind Authentication__: Using bind authentication will limit the attack surface of the LDAP server if an attacker manages to perform LDAP injection.

- __Least Privilege__: Least Privilege principle is a rule of the thumb advice to minimize the impact of compromised services.

=== "Java"
  ```java
  import java.util.Hashtable;
  import javax.naming.Context;
  import javax.naming.NamingEnumeration;
  import javax.naming.directory.*;
  
  public class LDAPSearchMitigatedExample {
  
      public static void main(String[] args) {
          // Input from the user (replace this with your own input mechanism)
          String userInput = "username"; // User-supplied input
  
          // LDAP connection parameters
          String ldapURL = "ldap://your-ldap-server:389";
          String baseDN = "ou=users,dc=example,dc=com"; // Replace with your base DN
  
          // Set up the environment for creating the initial context
          Hashtable<String, String> env = new Hashtable<>();
          env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
          env.put(Context.PROVIDER_URL, ldapURL);
  
          try {
              // Create the initial context
              LdapContext ctx = new InitialLdapContext(env, null);
  
              // Use parameterized query to avoid LDAP injection
              String searchFilter = "(uid={0})";
              Object[] filterArgs = {userInput};
  
              // Set the search controls
              SearchControls searchControls = new SearchControls();
              searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
  
              // Perform the search
              NamingEnumeration<SearchResult> results = ctx.search(baseDN, searchFilter, filterArgs, searchControls);
  
              // Iterate through the search results
              while (results.hasMore()) {
                  SearchResult result = results.next();
                  // Process the result as needed (e.g., print attributes)
                  Attributes attributes = result.getAttributes();
                  System.out.println("User found: " + attributes.get("cn").get());
              }
  
              // Close the context
              ctx.close();
          } catch (Exception e) {
              e.printStackTrace();
          }
      }
  }
  ```

=== "JavaScript"
  ```javascript
  // Mitigated JavaScript code with input validation and parameterized query
  const ldap = require('ldapjs');
  
  const userInput = 'user123';
  // Perform input validation to ensure userInput is safe for LDAP query
  if (isValidUserInput(userInput)) {
      const ldapQuery = `(uid=${userInput})`;
      const client = ldap.createClient({
          url: 'ldap://example.com:389'
      });
  
      client.search('ou=users,dc=example,dc=com', {
          filter: ldapQuery,
      }, (err, res) => {
          // Process search results
          res.on('searchEntry', (entry) => {
              // Handle entry
          });
  
          res.on('error', (err) => {
              console.error('Error:', err.message);
          });
      });
  } else {
      console.log('Invalid userInput');
  }
  
  function isValidUserInput(userInput) {
      // Implement proper input validation logic
      // For example, check for allowed characters, length, etc.
      return /^[a-zA-Z0-9]+$/.test(userInput);
  }
  ```

=== "PHP"
  ```php
  <?php
  // Mitigated PHP code with input validation and parameterized query
  $userInput = 'user123';
  // Perform input validation to ensure userInput is safe for LDAP query
  if (isValidUserInput($userInput)) {
      $ldapQuery = "(uid=$userInput)";
      $ldapconn = ldap_connect("ldap://example.com");
      ldap_bind($ldapconn, "cn=admin,dc=example,dc=com");
  
      $result = ldap_search($ldapconn, "ou=users,dc=example,dc=com", $ldapQuery);
      $entries = ldap_get_entries($ldapconn, $result);
  
      // Process search results
      foreach ($entries as $entry) {
          // Handle entry
      }
  
      ldap_close($ldapconn);
  } else {
      echo 'Invalid userInput';
  }
  
  function isValidUserInput($userInput) {
      // Implement proper input validation logic
      // For example, check for allowed characters, length, etc.
      return preg_match('/^[a-zA-Z0-9]+$/', $userInput);
  }
  ?>
  ```