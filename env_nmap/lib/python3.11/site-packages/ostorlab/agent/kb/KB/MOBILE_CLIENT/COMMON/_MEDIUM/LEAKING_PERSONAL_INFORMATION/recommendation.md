* When saving PII/PHI locally, make sure they're encrypted and encryption keys are stored in the KeyChain.
* Access to the PII information should be protected by biometric authentication.
* If applicable, avoid caching PII information locally, instead, query it from the backend servers.
* Securely delete PII/PHI when there is no longer a business need for its retention on the device.
* Consider encrypting and/or hashing PHI/PII data before saving it on the device.
* Provide users with way to withdraw consent for holding their PHI/PII data.
* Do not cache PII/PHI data.
* Minimize the use of third party libraries and APIs that access user data.
* Some jurisdictions may require you to provide a privacy policy for accessing personal information.
* If logging PII information is necessary, set the logging level to debug so that PII doesn't in production application logs.



=== "Kotlin"
  ```kotlin
  import android.os.Bundle
  import android.util.Log
  import androidx.appcompat.app.AppCompatActivity
  import kotlinx.android.synthetic.main.activity_main.*
  
  class MainActivity : AppCompatActivity() {
  
      override fun onCreate(savedInstanceState: Bundle?) {
          super.onCreate(savedInstanceState)
          setContentView(R.layout.activity_main)
  
          // Assuming you have EditText fields for username and password in your layout
          // with ids 'usernameEditText' and 'passwordEditText' respectively
  
          loginButton.setOnClickListener {
              val username = usernameEditText.text.toString()
              val password = passwordEditText.text.toString()
  
              // Log the user credentials
              Log.d("UserCredentials", "Username: $username, Password: $password")
  
              // Perform login logic here
              performLogin(username, password)
              
              // Clear the EditText fields after login
              usernameEditText.text.clear()
              passwordEditText.text.clear()
          }
      }
  }
  ```


=== "Swift"
  ```swift
  import UIKit
  import os.log
  
  class ViewController: UIViewController {
  
      @IBOutlet weak var usernameTextField: UITextField!
      @IBOutlet weak var passwordTextField: UITextField!
      
      override func viewDidLoad() {
          super.viewDidLoad()
          // Do any additional setup after loading the view.
      }
  
      @IBAction func loginButtonTapped(_ sender: UIButton) {
          guard let username = usernameTextField.text, !username.isEmpty,
                let password = passwordTextField.text, !password.isEmpty else {
              // Handle empty username or password
              return
          }
          
          // Log user credentials
          os_log_debug("Username: %@, Password: %@", log: .default, type: .info, username, password)
          
          // Perform login logic here
          performLogin(username, password)
          
          // Clear text fields after login
          usernameTextField.text = ""
          passwordTextField.text = ""
      }
  }
  ```


=== "Flutter"
  ```dart
  import 'package:flutter/material.dart';
  import 'package:flutter/services.dart';
  import 'package:logger/logger.dart';
  
  void main() {
    runApp(MyApp());
  }
  
  class MyApp extends StatelessWidget {
    @override
    Widget build(BuildContext context) {
      return MaterialApp(
        title: 'Login Example',
        theme: ThemeData(
          primarySwatch: Colors.blue,
        ),
        home: LoginPage(),
      );
    }
  }
  
  class LoginPage extends StatelessWidget {
    final TextEditingController _usernameController = TextEditingController();
    final TextEditingController _passwordController = TextEditingController();
  
    final logger = Logger(
      printer: PrettyPrinter(),
      output: FileOutput('login_log.txt'),
    );
  
    @override
    Widget build(BuildContext context) {
      return Scaffold(
        appBar: AppBar(
          title: Text('Login Page'),
        ),
        body: Padding(
          padding: EdgeInsets.all(20.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              TextField(
                controller: _usernameController,
                decoration: InputDecoration(
                  labelText: 'Username',
                ),
              ),
              SizedBox(height: 10.0),
              TextField(
                controller: _passwordController,
                decoration: InputDecoration(
                  labelText: 'Password',
                ),
                obscureText: true,
              ),
              SizedBox(height: 20.0),
              ElevatedButton(
                onPressed: () {
                  _login(context);
                },
                child: Text('Login'),
              ),
            ],
          ),
        ),
      );
    }
  
    void _login(BuildContext context) {
      final username = _usernameController.text;
      final password = _passwordController.text;
  
      // Log user credentials as information
      logger.d('Username: $username, Password: $password');
  
      // Perform login logic here
      performLogin(username, password)
  
      // Clear text fields after login
      _usernameController.clear();
      _passwordController.clear();
  
      // Optionally, you can navigate to another screen or perform other actions after successful login
    }
  }
  ```