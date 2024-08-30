`Webview.loadurl` loads a given URL into a webview session. Webview url
accepts different urls schemes and paths that can lead to loading of
insecure content, perform phishing attacks or in some cases exploit a
remote code execution vulnerability.

Several settings controls the capabilities of the webview session, like
enabling javascript or local file access using the `Websettings` class.

Attackers can exploit the vulnerability by crafting malicious HTML or
Javascript. A phishing attack can pass as a fake login form to steal the
user\'s credentials.

The following is an example a vulnerable Java code accepting untrusted
URL from an intent:

=== "Java"
	```java
	public class VulnerableBrowserActivity extends Activity {
	      @override
	      public void onCreate(Bundle savedInstanceState) {
	        super.onCreate(savedInstanceState);
	        setContentView(R.layout.main);
	
	        // Create a new wevbiew session.
	        WebView webView = (WebView) findViewById(R.id.webview);
	
	        // Enable javascript.
	        WebSettings settings = webView.getSettings();
	        settings.setJavaScriptEnabled(true);
	
	        // Accept url from untrusted intent.
	        String url = getIntent().getStringExtra("URL");
	        webView.loadUrl(url);
	      }
	    }
	```

