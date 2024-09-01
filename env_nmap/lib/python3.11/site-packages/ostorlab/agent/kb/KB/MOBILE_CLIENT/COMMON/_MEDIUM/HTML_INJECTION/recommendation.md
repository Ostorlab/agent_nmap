To mitigate the risks associated with HTML injection vulnerabilities, consider the following recommendations:

- **Contextual Output Encoding:** Encode user-generated content based on its context. Different contexts, such as HTML attributes, JavaScript code, or CSS styles, require specific encoding techniques to prevent HTML injection attacks. Use appropriate encoding functions or libraries based on the context.

- **Sanitize User Input:** Perform proper input validation and sanitization on user-supplied data by stripping any special HTML characters before rendering it as part of HTML code. 

- **Disable Javascript if not needed:** in the context of mobile webviews, disabling Javascript can help significantly reduce the impact of any potential HTML injection.

- **Use Logic-less Templating Engines:** Templating engines like `Mustache` can help prevent HTML injection by properly handling user input.


=== "Dart"
	```dart
	import 'package:flutter/material.dart';
	import 'package:webview_flutter/webview_flutter.dart';
	import 'package:sanitize_html/sanitize_html.dart' show sanitizeHtml;
	
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
	    Map<String, dynamic>? extras =
	        ModalRoute.of(context)?.settings.arguments as Map<String, dynamic>?;
	
	    // Extract the user input from the intent extras
	    htmlInput = extras?['htmlInput'];
	  }
	
	  void _injectHtml() async {
	    if (htmlInput != null) {
	      final sanitizedHtml = sanitizeHtml(htmlInput);
	      await _webViewController.loadUrl(
	        Uri.dataFromString(sanitizedHtml, mimeType: 'text/html', encoding: Encoding.getByName('utf-8'))!.toString(),
	      );
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
	```Swift
	import UIKit
	import WebKit
	
	class ViewController: UIViewController, WKNavigationDelegate {
			
			private var webView: WKWebView!
			
			override func viewDidLoad() {
					super.viewDidLoad()
					
					webView = WKWebView(frame: view.bounds)
					webView.navigationDelegate = self
					view.addSubview(webView)
					
					let name = "John Doe"
					let plainText = "Hello, \(name)!"
					let sanitizedText = sanitizeHTML(plainText)
					let html = "<html><body><h1>\(sanitizedText)</h1></body></html>"
					webView.loadHTMLString(html, baseURL: nil)
			}
			
			private func sanitizeHTML(_ html: String) -> String {
					// Replace any '<' and '>' characters with HTML entities
					let sanitized = html.replacingOccurrences(of: "<", with: "&lt;")
															.replacingOccurrences(of: ">", with: "&gt;")
					return sanitized
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
	
	    PolicyFactory policy = new HtmlPolicyBuilder()
	        .allowElements("a")
	        .allowUrlProtocols("https")
	        .allowAttributes("href").onElements("a")
	        .requireRelNofollowOnLinks()
	        .build();
	
	    override fun onCreate(savedInstanceState: Bundle?) {
	        super.onCreate(savedInstanceState)
	        setContentView(R.layout.activity_main)
	
	        webView = findViewById(R.id.webView)
	
	        val name = intent.getStringExtra("name")
	        val sanitizedName = policy.sanitize(name)   
	
	        val html = "<html><body><h1>Hello, $sanitizedName!</h1></body></html>"
	        webView.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)
	
	        val webSettings: WebSettings = webView.settings
	        webSettings.javaScriptEnabled = false
	    }
	
	}
	```
