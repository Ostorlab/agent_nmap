In cryptography, a cipher (or cypher) is an algorithm for performing encryption or decryption—a series of well-defined
steps that can be followed as a procedure.

There are typically two families:

* Blocker Cipher: A block cipher breaks down plaintext messages into fixed-size blocks before converting them into
  ciphertext using a key.
* Stream Cipher: A stream cipher, on the other hand, breaks a plaintext message down into single bits, which then are
  converted individually into ciphertext using key bits.

Common cipher algorithms:

* `DES` and `Triple DES`: Triple DES was designed to replace the original Data Encryption Standard (DES) algorithm,
  which hackers eventually learned to defeat with relative ease. At one time, Triple DES was the recommended standard
  and the most widely used symmetric algorithm in the industry. Triple DES uses three individual keys with 56 bits each.
  The total key length adds up to 168 bits, but experts would argue that 112-bits in key strength is more accurate.
  Despite slowly being phased out, Triple DES has, for the most part, been replaced by the Advanced Encryption
  Standard (AES).
* `AES`: The Advanced Encryption Standard (AES) is the algorithm trusted as the standard by the U.S. Government and
  numerous organizations. Although it is highly efficient in 128-bit form, AES also uses keys of 192 and 256 bits for
  heavy-duty encryption purposes. AES is largely considered impervious to all attacks, except for brute force, which
  attempts to decipher messages using all possible combinations in the 128, 192, or 256-bit cipher.
* `RSA`: RSA is a public-key encryption algorithm and the standard for encrypting data sent over the internet. It also
  happens to be one of the methods used in PGP and GPG programs. Unlike Triple DES, RSA is considered an asymmetric
  algorithm due to its use of a pair of keys. You've got your public key to encrypt the message and a private key to
  decrypt it. The result of RSA encryption is a huge batch of mumbo jumbo that takes attackers a lot of time and
  processing power to break.
* `ECC`: Elliptic Curve Cryptography (ECC) is a key-based technique for encrypting data. ECC focuses on pairs of public
  and private keys for decryption and encryption of web traffic. ECC is frequently discussed in the context of the
  Rivest–Shamir–Adleman (RSA) cryptographic algorithm. RSA achieves one-way encryption of things like emails, data, and
  software using prime factorization.

`DES`, `Triple DES` are insecure and must not be used. Other algorithms suffer from some weaknesses caused by insecure
cipher mode settings, key size or special key cases.

=== "Dart"
	```dart
	import 'dart:convert';
	import 'dart:typed_data';
	import 'package:flutter/material.dart';
	import 'package:flutter/services.dart';
	import 'package:crypto/crypto.dart';
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
	          title: Text('Insecure Encryption Demo'),
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
	    final key = utf8.encode('insecurekey');
	    final iv = Uint8List(8);
	    final s = pc.SICStreamCipher(pc.DESEngine())
	      ..init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
	    final input = utf8.encode(_controller.text);
	    final output = s.process(input);
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
	import CommonCrypto
	
	func DES_Encrypt(input: String, key: String) -> String {
	    let data = input.data(using: String.Encoding.utf8)!
	    let keyData = key.data(using: String.Encoding.utf8)!
	    let keyBytes = keyData.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
	        return bytes
	    }
	    let dataLength = Int(data.count)
	    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: dataLength + kCCBlockSizeDES)
	    let bufferPtr = UnsafeMutableRawPointer(buffer)
	    let bufferPtrBytes = bufferPtr.bindMemory(to: Void.self, capacity: dataLength)
	    let iv = [UInt8](repeating: 0, count: kCCBlockSizeDES)
	    var numBytesEncrypted :size_t = 0
	    let cryptStatus = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(kCCOptionPKCS7Padding), keyBytes, kCCKeySizeDES, iv, data.bytes, dataLength, bufferPtrBytes, dataLength + kCCBlockSizeDES, &numBytesEncrypted)
	    if UInt32(cryptStatus) == UInt32(kCCSuccess) {
	        let encryptedData = Data(bytes: UnsafePointer<UInt8>(buffer), count: numBytesEncrypted)
	        buffer.deallocate()
	        return encryptedData.base64EncodedString()
	    } else {
	        buffer.deallocate()
	        return ""
	    }
	}
	
	func main() {
	    print("Enter text to encrypt:")
	    let input = readLine() ?? ""
	    print("Enter encryption key:")
	    let key = readLine() ?? ""
	    let encrypted = DES_Encrypt(input: input, key: key)
	    print("Encrypted text: \(encrypted)")
	}
	
	main()
	```


=== "Kotlin"
	```kotlin
	import javax.crypto.Cipher
	import javax.crypto.SecretKey
	import javax.crypto.SecretKeyFactory
	import javax.crypto.spec.DESKeySpec
	import java.util.*
	
	fun main(args: Array<String>) {
	    val scanner = Scanner(System.`in`)
	    println("Enter text to encrypt:")
	    val text = scanner.nextLine()
	    println("Enter DES key:")
	    val key = scanner.nextLine()
	
	    val encryptedText = encrypt(text, key)
	    println("Encrypted text: $encryptedText")
	
	    val decryptedText = decrypt(encryptedText, key)
	    println("Decrypted text: $decryptedText")
	}
	
	fun encrypt(text: String, key: String): String {
	    val desKey = SecretKeyFactory.getInstance("DES").generateSecret(DESKeySpec(key.toByteArray()))
	    val cipher = Cipher.getInstance("DES")
	    cipher.init(Cipher.ENCRYPT_MODE, desKey)
	    return Base64.getEncoder().encodeToString(cipher.doFinal(text.toByteArray()))
	}
	
	fun decrypt(text: String, key: String): String {
	    val desKey = SecretKeyFactory.getInstance("DES").generateSecret(DESKeySpec(key.toByteArray()))
	    val cipher = Cipher.getInstance("DES")
	    cipher.init(Cipher.DECRYPT_MODE, desKey)
	    return String(cipher.doFinal(Base64.getDecoder().decode(text)))
	}
	```
