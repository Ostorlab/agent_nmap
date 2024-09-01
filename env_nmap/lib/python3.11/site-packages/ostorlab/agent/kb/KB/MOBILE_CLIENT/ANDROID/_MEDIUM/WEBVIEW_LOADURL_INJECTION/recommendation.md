All untrusted URLs must have proper input validation to ensure only
trusted content is accessible. For instance, if the application is
loading local assets, the list of loaded URL must be whitelisted.

The `Webview` settings must also be hardened, removing all non required
settings, like javascript or file access.

=== "Java"
	```java
	public class WhitelistBrowserActivity extends Activity {
	  private static WHITELISTED_URLS = ImmutableList.of(
	    "url1",
	    "url2");
	
	  @override
	  public void onCreate(Bundle savedInstanceState) {
	    super.onCreate(savedInstanceState);
	    setContentView(R.layout.main);
	
	    WebView webView = (WebView) findViewById(R.id.webview);
	
	    String url = getIntent().getStringExtra("url");
	    if (!WHITELISTED_URLS.contains(url)) {  /* Note: "https".startsWith("http") == true */
	        url = "about:blank";
	    }
	
	    webView.loadUrl(url);
	  }
	}
	```

