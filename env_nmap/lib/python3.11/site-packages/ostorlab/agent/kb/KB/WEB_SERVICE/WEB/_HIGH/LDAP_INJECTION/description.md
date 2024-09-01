LDAP Injection involves exploiting web-based applications that generate LDAP statements using user input. In cases where an application fails to properly sanitize user input, attackers can manipulate LDAP statements by injecting special keywords into the query, an attack that is similar to SQL Injection.


=== "Java"
  ```java
  import java.util.Hashtable;
  import javax.naming.Context;
  import javax.naming.NamingEnumeration;
  import javax.naming.directory.*;
  
  public class LDAPSearchExample {
  
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
  
              // Specify the search filter
              String searchFilter = "(uid=" + userInput + ")";
              
              // Set the search controls
              SearchControls searchControls = new SearchControls();
              searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
  
              // Perform the search
              NamingEnumeration<SearchResult> results = ctx.search(baseDN, searchFilter, searchControls);
  
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
  const ldap = require('ldapjs');
  
  const userInput = 'user123';
  const ldapQuery = `(uid=${userInput})`; // Vulnerable to LDAP Injection
  
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
  ```

=== "PHP"
  ```php
  <?php
  // Vulnerable PHP code with LDAP Injection
  $userInput = 'user123';
  $ldapQuery = "(uid=$userInput)"; // Vulnerable to LDAP Injection
  
  $ldapconn = ldap_connect("ldap://example.com");
  ldap_bind($ldapconn, "cn=admin,dc=example,dc=com", "adminpassword");
  
  $result = ldap_search($ldapconn, "ou=users,dc=example,dc=com", $ldapQuery);
  $entries = ldap_get_entries($ldapconn, $result);
  
  // Process search results
  foreach ($entries as $entry) {
      // Handle entry
  }
  
  ldap_close($ldapconn);
  ?>
  ```

