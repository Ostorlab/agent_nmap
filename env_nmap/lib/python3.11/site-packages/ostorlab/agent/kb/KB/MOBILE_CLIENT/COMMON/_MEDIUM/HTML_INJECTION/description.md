HTML injection is a security vulnerability that occurs when user-manipulated input in a mobile application can be used to insert arbitrary HTML code into a vulnerable webview. This vulnerability can be exploited to launch various attacks, such as stealing a user's session tokens or CSRF tokens, which can then be used for further malicious activities. Additionally, it allows attackers to modify the content displayed to victims, giving them the ability to insert malicious code or deface the page with their own message.

=== "Dart"
	```dart
	import 'package:flutter/material.dart';
	import 'package:webview_flutter/webview_flutter.dart';
	
	void main() => runApp(MyApp());
	
	class MyApp extends StatelessWidget {
	  @override
	  Widget build(BuildContext context) {
	    return MaterialApp(
	      title: 'HTML Injection Demo',
	      theme: ThemeData(
	        primarySwatch: Colors.blue,
	      ),
	      home: WebViewScreen(),
	    );
	  }
	}
	
	class WebViewScreen extends StatefulWidget {
	  @override
	  _WebViewScreenState createState() => _WebViewScreenState();
	}
	
	class _WebViewScreenState extends State<WebViewScreen> {
	  late WebViewController _webViewController;
	  String? htmlInput;
	
	  @override
	  void initState() {
	    super.initState();
	    getHtmlInputFromIntent();
	  }
	
	  void getHtmlInputFromIntent() {
	    // Retrieve the intent extras
	    Map<String, dynamic>? extras = ModalRoute.of(context)?.settings.arguments as Map<String, dynamic>?;
	
	    // Extract the user input from the intent extras
	    htmlInput = extras?['htmlInput'];
	  }
	
	  void _injectHtml() async {
	    if (htmlInput != null) {
	      await _webViewController.loadUrl(Uri.dataFromString(htmlInput!, mimeType: 'text/html').toString());
	    }
	  }
	
	  @override
	  Widget build(BuildContext context) {
	    return Scaffold(
	      appBar: AppBar(
	        title: Text('HTML Injection Demo'),
	      ),
	      body: Column(
	        children: [
	          ElevatedButton(
	            onPressed: _injectHtml,
	            child: Text('Inject HTML'),
	          ),
	          Expanded(
	            child: WebView(
	              initialUrl: 'about:blank',
	              onWebViewCreated: (WebViewController controller) {
	                _webViewController = controller;
	              },
	            ),
	          ),
	        ],
	      ),
	    );
	  }
	}
	```


=== "Swift"
	```swift
	import UIKit
	import WebKit
	
	class ViewController: UIViewController, WKNavigationDelegate {
	
	    var webView: WKWebView!
	    var htmlInput: String?
	
	    override func viewDidLoad() {
	        super.viewDidLoad()
	
	        // Retrieve the user input from the intent extras
	        if let extras = self.navigationController?.navigationBar.accessibilityUserInputLabels {
	            htmlInput = extras["htmlInput"] as? String
	        }
	
	        // Create and configure the web view
	        webView = WKWebView(frame: view.bounds)
	        webView.navigationDelegate = self
	        view.addSubview(webView)
	
	        // Load the web page
	        let htmlString = "<html><body><h1>\(htmlInput ?? "")</h1></body></html>"
	        webView.loadHTMLString(htmlString, baseURL: nil)
	    }
	}
	```



=== "Kotlin"
	```kotlin
	import android.annotation.SuppressLint
	import android.os.Bundle
	import android.webkit.WebSettings
	import android.webkit.WebView
	import androidx.appcompat.app.AppCompatActivity
	
	class MainActivity : AppCompatActivity() {
	
	    private lateinit var webView: WebView
	
	    override fun onCreate(savedInstanceState: Bundle?) {
	        super.onCreate(savedInstanceState)
	        setContentView(R.layout.activity_main)
	
	        webView = findViewById(R.id.webView)
	
	        val name = intent.getStringExtra("name")
	
	        val html = "<html><body><h1>Hello, $name!</h1></body></html>"
	        webView.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)
	
	        val webSettings: WebSettings = webView.settings
	        webSettings.javaScriptEnabled = false
	    }
	}
	```

