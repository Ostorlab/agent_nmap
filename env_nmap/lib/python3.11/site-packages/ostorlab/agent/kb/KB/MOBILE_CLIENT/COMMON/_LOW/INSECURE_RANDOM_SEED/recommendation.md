To ensure generated random values are not predictable, use secure Pseudo Random Number Generators (PRNGs) like `SecureRandom` for Java and `SecRandomCopyBytes` for Swift. 

=== "Java"
  ```java
  import java.security.SecureRandom;
  
  public class SecureRandomExample {
      public static void main(String[] args) {
          SecureRandom secureRandom = new SecureRandom();
          
          // Generating a random integer
          int randomNumber = secureRandom.nextInt();
          System.out.println("Random Integer: " + randomNumber);
          
          // Generating a random double
          double randomDouble = secureRandom.nextDouble();
          System.out.println("Random Double: " + randomDouble);
          
          // Generating a random byte array
          byte[] randomBytes = new byte[10];
          secureRandom.nextBytes(randomBytes);
          System.out.println("Random Bytes: " + java.util.Arrays.toString(randomBytes));
      }
  }
  ```

=== "Swift"
  ```swift
  import Security

  func generateRandomBytes(count: Int) -> [UInt8]? {
      var randomBytes = [UInt8](repeating: 0, count: count)
      let status = SecRandomCopyBytes(kSecRandomDefault, count, &randomBytes)
      
      guard status == errSecSuccess else {
          print("Error generating random bytes: \(status)")
          return nil
      }
      
      return randomBytes
  }
  
  if let randomBytes = generateRandomBytes(count: 10) {
      print("Random Bytes: \(randomBytes)")
  }
  ```