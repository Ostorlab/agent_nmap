Insecure storage vulnerability in mobile applications refers to a security flaw where sensitive data, such as user credentials, personal information, or other confidential data, is stored on the device in world readable locations. This can leave the data vulnerable to unauthorized access by other applications on the device or by a malicious actor with physical access to the device.

Insecure storage does not only occur when the application writes to world-readable locations but also when the application loads data such as configuration files from world-writable locations where a malicious actor can alter the configuration files and consequently tamper with the functionality of the application. 



=== "Kotlin"
  ```kotlin
  import android.os.Bundle
  import android.os.Environment
  import android.widget.Button
  import android.widget.Toast
  import androidx.appcompat.app.AppCompatActivity
  import java.io.File
  import java.io.FileOutputStream
  import java.io.IOException
  import java.io.OutputStreamWriter
  
  class MainActivity : AppCompatActivity() {
  
      override fun onCreate(savedInstanceState: Bundle?) {
          super.onCreate(savedInstanceState)
          setContentView(R.layout.activity_main)
  
          val loginButton: Button = findViewById(R.id.login_button)
          loginButton.setOnClickListener {
              // Dummy authentication process
              val token = authenticate("username", "password") // authentication logic
  
              // Store token in public storage
              storeTokenInPublicStorage(token)
          }
      }
  
      private fun storeTokenInPublicStorage(token: String) {
          val filePath = "/sdcard/insecure_app/jwt_config.txt"
          val file = File(filePath)
          try {
              val outputStreamWriter = OutputStreamWriter(FileOutputStream(file))
              outputStreamWriter.write(token)
              outputStreamWriter.close()
          } catch (e: IOException) {
              e.printStackTrace()
          }
      }
  }
  ```


=== "Swift"
  ```swift
  import UIKit
  
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
  
          // Store token in public storage
          storeTokenInPublicStorage(token: token)
      }
      
      
      private func storeTokenInPublicStorage(token: String) {
          let filePath = "/var/mobile/Media/insecure_app/jwt_config.txt"
          let fileURL = URL(fileURLWithPath: filePath)
          
          do {
              try token.write(to: fileURL, atomically: true, encoding: .utf8)
              print("Token stored successfully.")
          } catch {
              print("Failed to write token: \(error)")
          }
      }
  }
  ```


=== "Flutter"
  ```dart
  import 'dart:io';
  import 'package:flutter/material.dart';
  
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
    @override
    Widget build(BuildContext context) {
      return Scaffold(
        appBar: AppBar(
          title: Text('Flutter Insecure Storage'),
        ),
        body: Center(
          child: ElevatedButton(
            onPressed: () {
              // Dummy authentication process
              String token = authenticate("username", "password");
  
              // Store token in public storage
              storeTokenInPublicStorage(token);
            },
            child: Text('Login'),
          ),
        ),
      );
    }
  
    void storeTokenInPublicStorage(String token) {
      final directory = Directory('/sdcard/insecure_app/');
      directory.createSync(recursive: true);
      final file = File('${directory.path}/jwt_config.txt');
      try {
        file.writeAsStringSync(token);
        print('Token stored successfully.');
      } catch (e) {
        print('Failed to write token: $e');
      }
    }
  }
  ```
