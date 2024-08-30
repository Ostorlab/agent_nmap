Personally Identifiable Information (PII) is, according to NIST Special Publication 800-122, a collective term for any information that can be used to distinguish or trace an individual's identity, such as name, social security number, date and place of birth, mother's maiden name, or biometric records; and any other information that is linked or linkable to an individual, such as medical, educational, financial, and employment information.

In the context of mobile security, PII leakage occurs when plain text PII information is logged to application logs or a world-readable file making it accessible to all applications on the user device.

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
              Log.i("UserCredentials", "Username: $username, Password: $password")
  
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
          os_log_info("Username: %@, Password: %@", log: .default, type: .info, username, password)
          
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
      logger.i('Username: $username, Password: $password');
  
      // Perform login logic here
      performLogin(username, password)
  
      // Clear text fields after login
      _usernameController.clear();
      _passwordController.clear();
  
      // Optionally, you can navigate to another screen or perform other actions after successful login
    }
  }
  ```