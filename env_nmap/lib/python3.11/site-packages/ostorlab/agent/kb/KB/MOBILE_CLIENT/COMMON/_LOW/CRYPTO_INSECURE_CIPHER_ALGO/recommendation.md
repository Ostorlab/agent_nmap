For secure and reliable encryption, it is crucial to use modern and robust cryptographic algorithms that have undergone extensive scrutiny and are widely adopted by the industry. Two recommended alternatives to the insecure DES and Triple DES are the Advanced Encryption Standard (AES) and Elliptic Curve Cryptography (ECC).

AES is widely recognized as a highly efficient and secure symmetric encryption algorithm. It offers key lengths of 128, 192, and 256 bits, making it suitable for various encryption purposes. AES has proven to be resilient against most known attacks, making it an excellent choice for data protection.

ECC, on the other hand, is an asymmetric encryption technique that uses pairs of public and private keys for encryption and decryption. ECC is known for providing strong security with shorter key lengths compared to other asymmetric algorithms like RSA. This results in faster encryption and decryption processes while maintaining a high level of security.

To ensure the utmost security when using any cryptographic algorithm, it is essential to follow best practices:

- Key Length: Use key lengths that are considered secure. For AES, 128 bits are sufficient for most use cases, but you can opt for 192 or 256 bits for more sensitive data.

- Cipher Mode: Always employ secure cipher mode settings, such as AES-GCM (Galois/Counter Mode) or AES-CBC (Cipher Block Chaining) with appropriate padding.

- Key Management: Use secure storage mechanisms (Keystore for Android, Keychain for iOS) to safely store cryptographic keys.


=== "Dart"
	```dart
	import 'dart:convert';
	import 'dart:typed_data';
	import 'package:flutter/material.dart';
	import 'package:flutter/services.dart';
	import 'package:pointycastle/export.dart' as pc;
	
	void main() {
	  runApp(MyApp());
	}
	
	class MyApp extends StatelessWidget {
	  @override
	  Widget build(BuildContext context) {
	    return MaterialApp(
	      home: Scaffold(
	        appBar: AppBar(
	          title: Text('Secure Encryption Demo'),
	        ),
	        body: EncryptionWidget(),
	      ),
	    );
	  }
	}
	
	class EncryptionWidget extends StatefulWidget {
	  @override
	  _EncryptionWidgetState createState() => _EncryptionWidgetState();
	}
	
	class _EncryptionWidgetState extends State<EncryptionWidget> {
	  final _controller = TextEditingController();
	  String _encryptedText = '';
	
	  void _encryptText() {
	    final key = pc.KeyParameter(Uint8List.fromList(utf8.encode('securekey123456789012345678901234'))); // 32 bytes for AES-256
	    final iv = Uint8List(12); // 12 bytes for GCM IV
	    final cipher = pc.GCMBlockCipher(pc.AESFastEngine())
	      ..init(true, pc.AEADParameters(key, 128, iv));
	    final input = utf8.encode(_controller.text);
	    final output = cipher.process(Uint8List.fromList(input));
	    setState(() {
	      _encryptedText = base64.encode(output);
	    });
	  }
	
	  @override
	  Widget build(BuildContext context) {
	    return Column(
	      children: <Widget>[
	        TextField(
	          controller: _controller,
	          decoration: InputDecoration(
	            labelText: 'Enter text to encrypt',
	          ),
	        ),
	        RaisedButton(
	          onPressed: _encryptText,
	          child: Text('Encrypt'),
	        ),
	        Text('Encrypted text: $_encryptedText'),
	      ],
	    );
	  }
	}
	```


=== "Swift"
	```swift
	import Foundation
	import CryptoKit
	
	func AES_GCM_Encrypt(input: String, key: String) -> String {
	    guard let data = input.data(using: .utf8),
	          let keyData = key.data(using: .utf8) else {
	        return ""
	    }
	    
	    let iv = Data(count: AES.GCM.nonceSize)
	    
	    do {
	        let sealedData = try! AES.GCM.seal(plainData!, using: key, nonce: AES.GCM.Nonce(data:nonce!))
	        let encryptedContent = try! sealedData.combined!
	        return sealedData.ciphertext.base64EncodedString()
	    } catch {
	        return ""
	    }
	}
	
	print("Enter text to encrypt:")
	if let input = readLine() {
	    print("Enter encryption key:")
	    if let key = readLine() {
	        let encrypted = AES_GCM_Encrypt(input: input, key: key)
	        print("Encrypted text: \(encrypted)")
	    }
	}
	```


=== "Kotlin"
	```kotlin
	import java.security.SecureRandom
	import javax.crypto.Cipher
	import javax.crypto.SecretKey
	import javax.crypto.SecretKeyFactory
	import javax.crypto.spec.GCMParameterSpec
	import javax.crypto.spec.PBEKeySpec
	import javax.crypto.spec.SecretKeySpec
	import java.security.spec.KeySpec
	import java.util.*
	
	fun main(args: Array<String>) {
	    val scanner = Scanner(System.`in`)
	    println("Enter text to encrypt:")
	    val text = scanner.nextLine()
	    println("Enter AES key:")
	    val key = scanner.nextLine()
	
	    val salt = ByteArray(16)
	    SecureRandom().nextBytes(salt)
	    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
	    val spec: KeySpec = PBEKeySpec(key.toCharArray(), salt, 65536, 256)
	    val secretKey = factory.generateSecret(spec)
	    val secretKeySpec = SecretKeySpec(secretKey.encoded, "AES")
	
	    val encryptedText = encrypt(text, secretKeySpec)
	    println("Encrypted text: $encryptedText")
	
	    val decryptedText = decrypt(encryptedText, secretKeySpec)
	    println("Decrypted text: $decryptedText")
	}
	
	fun encrypt(text: String, key: SecretKey): String {
	    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
	    val iv = ByteArray(12)
	    SecureRandom().nextBytes(iv)
	    val gcmSpec = GCMParameterSpec(128, iv)
	    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
	    val encryptedBytes = cipher.doFinal(text.toByteArray())
	    val encryptedTextAndIV = ByteArray(iv.size + encryptedBytes.size)
	    System.arraycopy(iv, 0, encryptedTextAndIV, 0, iv.size)
	    System.arraycopy(encryptedBytes, 0, encryptedTextAndIV, iv.size, encryptedBytes.size)
	    return Base64.getEncoder().encodeToString(encryptedTextAndIV)
	}
	
	fun decrypt(text: String, key: SecretKey): String {
	    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
	    val decodedText = Base64.getDecoder().decode(text)
	    val iv = decodedText.copyOfRange(0, 12)
	    val encryptedBytes = decodedText.copyOfRange(12, decodedText.size)
	    val gcmSpec = GCMParameterSpec(128, iv)
	    cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
	    return String(cipher.doFinal(encryptedBytes))
	}
	```
