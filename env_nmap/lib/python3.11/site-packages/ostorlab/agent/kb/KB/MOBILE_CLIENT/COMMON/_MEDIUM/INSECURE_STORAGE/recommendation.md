- Use Secure Storage: Store sensitive data such as authentication tokens or credentials securely. Use secure storage mechanisms provided by the platform, such as Keychain for iOS and SharedPreferences with encryption for Android.
- Data Encryption: Encrypt sensitive data at rest using strong encryption algorithms to protect data stored on user device.
- Avoid Hardcoding Sensitive Information: Instead of hardcoding sensitive information like usernames, passwords, or tokens directly into your code, consider secure storage mechanisms suggested above.
- Avoid Permissive File Permissions: Ensure that file permissions are set appropriately to restrict access to sensitive files and directories. On Android for example, avoid using `MODE_WORLD_READABLE` or `MODE_WORLD_WRITEABLE` when creating files, as they grant broad read or write access to all applications. Always follow the principle of least privilege when setting file permissions and limit access to only what is necessary for the application's functionality.
- Input Validation: When loading data from public storage locations, always make sure to validate and sanitize it. 


=== "Kotlin"
  ```kotlin
  import android.content.Context
  import android.os.Bundle
  import android.widget.Button
  import android.widget.Toast
  import androidx.appcompat.app.AppCompatActivity
  import androidx.security.crypto.EncryptedSharedPreferences
  import androidx.security.crypto.MasterKeys
  import java.io.IOException
  
  class MainActivity : AppCompatActivity() {
  
      private lateinit var encryptedSharedPreferences: SharedPreferences
  
      override fun onCreate(savedInstanceState: Bundle?) {
          super.onCreate(savedInstanceState)
          setContentView(R.layout.activity_main)
  
          // Initialize encrypted shared preferences
          initializeEncryptedSharedPreferences()
  
          val loginButton: Button = findViewById(R.id.login_button)
          loginButton.setOnClickListener {
              // Dummy authentication process
              val token = authenticate("username", "password") // authentication logic
  
              // Store token securely in encrypted shared preferences
              storeTokenInSharedPreferences(token)
          }
      }
  
      private fun initializeEncryptedSharedPreferences() {
          try {
              val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
              encryptedSharedPreferences = EncryptedSharedPreferences.create(
                  "secure_preferences",
                  masterKeyAlias,
                  applicationContext,
                  EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                  EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
              )
          } catch (e: IOException) {
              e.printStackTrace()
          }
      }
  
      private fun storeTokenInSharedPreferences(token: String) {
          encryptedSharedPreferences.edit().putString("jwt_token", token).apply()
          Toast.makeText(this, "Token stored securely.", Toast.LENGTH_SHORT).show()
      }
  }
  ```


=== "Swift"
  ```swift
  import UIKit
  import Security
  
  class ViewController: UIViewController {
  
      override func viewDidLoad() {
          super.viewDidLoad()
          // Do any additional setup after loading the view.
          
          let loginButton = UIButton(type: .system)
          loginButton.setTitle("Login", for: .normal)
          loginButton.addTarget(self, action: #selector(loginButtonTapped), for: .touchUpInside)
          view.addSubview(loginButton)
          loginButton.translatesAutoresizingMaskIntoConstraints = false
          loginButton.centerXAnchor.constraint(equalTo: view.centerXAnchor).isActive = true
          loginButton.centerYAnchor.constraint(equalTo: view.centerYAnchor).isActive = true
      }
  
      @objc func loginButtonTapped() {
          // Dummy authentication process
          let token = authenticate(username: "username", password: "password")
  
          // Store token securely in Keychain
          storeTokenInKeychain(token: token)
      }

      private func storeTokenInKeychain(token: String) {
          let keychainQuery: [String: Any] = [
              kSecClass as String: kSecClassGenericPassword,
              kSecAttrAccount as String: "jwtToken",
              kSecValueData as String: token.data(using: .utf8)!,
              kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
          ]
          
          let status = SecItemAdd(keychainQuery as CFDictionary, nil)
          if status == errSecSuccess {
              print("Token stored securely in Keychain.")
          } else {
              print("Failed to store token in Keychain: \(status)")
          }
      }
  }
  ```


=== "Flutter"
  ```dart
  import 'package:flutter/material.dart';
  import 'package:flutter_secure_storage/flutter_secure_storage.dart';
  
  void main() {
    runApp(MyApp());
  }
  
  class MyApp extends StatelessWidget {
    @override
    Widget build(BuildContext context) {
      return MaterialApp(
        home: MyHomePage(),
      );
    }
  }
  
  class MyHomePage extends StatelessWidget {
    final storage = FlutterSecureStorage();
  
    @override
    Widget build(BuildContext context) {
      return Scaffold(
        appBar: AppBar(
          title: Text('Flutter Secure Storage Example'),
        ),
        body: Center(
          child: ElevatedButton(
            onPressed: () async {
              // Dummy authentication process
              String token = await authenticate("username", "password");
  
              // Store token securely
              await storeTokenInSecureStorage(token);
            },
            child: Text('Login'),
          ),
        ),
      );
    }
  
    Future<void> storeTokenInSecureStorage(String token) async {
      await storage.write(key: 'jwtToken', value: token);
      print('Token stored securely.');
    }
  }
  ```