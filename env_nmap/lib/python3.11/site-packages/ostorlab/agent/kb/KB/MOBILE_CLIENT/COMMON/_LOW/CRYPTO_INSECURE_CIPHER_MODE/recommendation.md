When using AES encryption, it is important to choose the correct mode of operation to ensure the confidentiality and integrity of the encrypted data. The choice of mode can depend on the specific use case and security requirements. Here are some common encryption modes to consider:

* `Electronic Codebook (ECB)`: This is the simplest mode and involves dividing the plaintext into blocks and encrypting each block separately using the same key. However, this mode is vulnerable to attacks as identical plaintext blocks will produce identical ciphertext blocks.
* `Cipher Block Chaining (CBC)`: In this mode, each plaintext block is XORed with the previous ciphertext block before encryption. This adds randomness and makes it harder to identify patterns in the encrypted data. However, this mode is vulnerable to attacks if the same IV (initialization vector) is used multiple times or initialized to non-random value.
* `Counter (CTR)`: This mode involves encrypting a counter value and XORing it with the plaintext to generate the ciphertext. This is a popular mode for streaming applications as it allows for parallel encryption and decryption. However, it requires unique counter values and can be vulnerable if an attacker can guess the counter values.
* `Galois/Counter Mode (GCM)`: This mode provides both confidentiality and integrity protection by using a combination of CTR mode and a message authentication code (MAC). It uses a unique IV and incorporates additional data such as a sequence number to prevent replay attacks. This mode is commonly used in applications that require both confidentiality and integrity protection.

In general, it is recommended to use `GCM` mode for `AES` encryption as it provides both confidentiality and integrity protection. However, it is important to properly manage the key and IV to ensure security. 

Using authenticated encryption modes such as `GCM` can help thwart attacks such as padding oracle attacks.


=== "Kotlin"
  ```kotlin
  import javax.crypto.Cipher
  import javax.crypto.spec.GCMParameterSpec
  import javax.crypto.spec.SecretKeySpec
  import java.security.SecureRandom
  import java.util.Base64
  
  fun encrypt(plaintext: String, key: ByteArray): String {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val random = SecureRandom()
      val iv = ByteArray(12)
      random.nextBytes(iv)
      val ivSpec = GCMParameterSpec(128, iv)
      val secretKey = SecretKeySpec(key, "AES")
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
      val encryptedBytes = cipher.doFinal(plaintext.toByteArray())
      val combined = ByteArray(iv.size + encryptedBytes.size)
      System.arraycopy(iv, 0, combined, 0, iv.size)
      System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)
      return Base64.getEncoder().encodeToString(combined)
  }
  
  fun decrypt(ciphertext: String, key: ByteArray): String {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val combined = Base64.getDecoder().decode(ciphertext)
      val iv = combined.copyOfRange(0, 12)
      val ivSpec = GCMParameterSpec(128, iv)
      val secretKey = SecretKeySpec(key, "AES")
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
      val decryptedBytes = cipher.doFinal(combined.copyOfRange(12, combined.size))
      return String(decryptedBytes)
  }
  
  fun main() {
      val key = "01234567890123456789012345678901".toByteArray()
      val plaintext = "Hello, world!"
      val encryptedText = encrypt(plaintext, key)
      println("Encrypted: $encryptedText")
      val decryptedText = decrypt(encryptedText, key)
      println("Decrypted: $decryptedText")
  }
  ```


=== "Swift"
  ```swift
  import Foundation
  import CryptoKit
  
  func encrypt(plaintext: String, key: SymmetricKey) throws -> Data {
      let sealedBox = try AES.GCM.seal(plaintext.data(using: .utf8)!, using: key)
      return sealedBox.combined!
  }
  
  func decrypt(ciphertext: Data, key: SymmetricKey) throws -> String {
      let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
      let decryptedData = try AES.GCM.open(sealedBox, using: key)
      return String(data: decryptedData, encoding: .utf8)!
  }
  
  func main() {
      let key = SymmetricKey(size: .bits256)
      let plaintext = "Hello, world!"
      let encryptedData = try! encrypt(plaintext: plaintext, key: key)
      print("Encrypted: \(encryptedData.base64EncodedString())")
      let decryptedText = try! decrypt(ciphertext: encryptedData, key: key)
      print("Decrypted: \(decryptedText)")
  }
  
  main()
  ```

=== "Flutter"
  ```flutter
  import 'dart:convert';
  import 'dart:typed_data';
  import 'package:pointycastle/export.dart';
  
  Uint8List encrypt(Uint8List plaintext, Uint8List key) {
    final cipher = GCMBlockCipher(AESFastEngine());
    final parameters = AEADParameters(KeyParameter(key), 128, Uint8List(12));
    cipher.init(true, parameters);
    final encrypted = cipher.process(plaintext);
    final Uint8List iv = parameters.nonce;
    final combined = Uint8List(iv.length + encrypted.length);
    combined.setRange(0, iv.length, iv);
    combined.setRange(iv.length, combined.length, encrypted);
    return combined;
  }
  
  Uint8List decrypt(Uint8List ciphertext, Uint8List key) {
    final cipher = GCMBlockCipher(AESFastEngine());
    final parameters = AEADParameters(KeyParameter(key), 128, Uint8List(12));
    cipher.init(false, parameters);
    final Uint8List iv = ciphertext.sublist(0, 12);
    final encrypted = ciphertext.sublist(12);
    final decrypted = cipher.process(Uint8List.fromList(encrypted));
    return decrypted;
  }
  
  void main() {
    final key = Uint8List.fromList(List.generate(32, (index) => index)); // Your 256-bit key
    final plaintext = 'Hello, world!';
    final plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));
    final encrypted = encrypt(plaintextBytes, key);
    print('Encrypted: ${base64Encode(encrypted)}');
    final decrypted = decrypt(encrypted, key);
    print('Decrypted: ${utf8.decode(decrypted)}');
  }
  ```