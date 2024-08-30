It is crucial to take proactive measures to protect your applications from URL manipulation attacks. Consider the following recommendations:

* Input Validation: Implement strict input validation mechanisms to ensure that URLs used for content fetching are properly formatted and adhere to expected patterns. This can include checking for valid URL schemes, enforcing expected domain names, and validating query parameters.
* Whitelist Approach: Maintain a whitelist of trusted domains or sources from which your application fetches content. Only allow requests to these trusted sources to minimize the risk of accessing malicious or unauthorized content.
* Content Integrity Checks: Implement mechanisms to verify the integrity of the fetched content. Calculate and compare cryptographic hashes or digital signatures of the received content against expected values to detect any modifications or tampering.

By implementing these recommendations, you can enhance the security of your applications, protect user data, and mitigate the risks associated with URL manipulation attacks.

Below is sample code implement whitelist validation:


=== "Dart"
	```dart
	import 'package:flutter/material.dart';
	import 'package:http/http.dart' as http;
	
	class MainActivity extends StatefulWidget {
	  final String url;
	  final List<String> allowedDomains;
	
	  MainActivity({required this.url, required this.allowedDomains});
	
	  @override
	  _MainActivityState createState() => _MainActivityState();
	}
	
	class _MainActivityState extends State<MainActivity> {
	  String? content;
	
	  @override
	  void initState() {
	    super.initState();
	    if (isDomainAllowed(widget.url)) {
	      fetchContent(widget.url);
	    } else {
	      // Handle unauthorized domain
	      // TODO: Implement appropriate action for unauthorized domain
	    }
	  }
	
	  bool isDomainAllowed(String urlString) {
	    Uri uri = Uri.parse(urlString);
	    String domain = uri.host ?? '';
	    return widget.allowedDomains.contains(domain);
	  }
	
	  Future<void> fetchContent(String url) async {
	    try {
	      final response = await http.get(Uri.parse(url));
	
	      if (response.statusCode == 200) {
	        setState(() {
	          content = response.body;
	        });
	        // TODO: Process the fetched content here
	      } else {
	        // Handle error response
	      }
	    } catch (e) {
	      // Handle network or API call error
	    }
	  }
	
	  @override
	  Widget build(BuildContext context) {
	    return Scaffold(
	      appBar: AppBar(
	        title: Text('Fetching URL Content'),
	      ),
	      body: Center(
	        child: content != null
	            ? Text(content!)
	            : CircularProgressIndicator(),
	      ),
	    );
	  }
	}
	```


=== "Swift"
	```swift
	import UIKit
	
	class AppDelegate: UIResponder, UIApplicationDelegate {
	
	    var window: UIWindow?
	    let allowedDomains = ["example.com", "trusteddomain.com"] // Add your trusted domain names here
	
	    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
	        // Handle deep link URL if the app was launched from a URL
	        if let url = launchOptions?[.url] as? URL {
	            handleDeepLink(url)
	        }
	        return true
	    }
	
	    func application(_ application: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
	        // Handle deep link URL when the app is already running
	        handleDeepLink(url)
	        return true
	    }
	
	    private func handleDeepLink(_ url: URL) {
	        // Check if the URL scheme is "ostorlab"
	        if url.scheme == "ostorlab" {
	            // Extract the URL from the deep link
	            if let deepLinkURL = URL(string: url.absoluteString.replacingOccurrences(of: "ostorlab://", with: "")) {
	                // Verify the domain name against the whitelist
	                if isDomainAllowed(deepLinkURL) {
	                    // Fetch the content from the provided URL
	                    fetchContent(deepLinkURL)
	                } else {
	                    // Handle unauthorized domain
	                    // TODO: Implement appropriate action for unauthorized domain
	                }
	            }
	        }
	    }
	
	    private func isDomainAllowed(_ url: URL) -> Bool {
	        guard let host = url.host else {
	            return false
	        }
	        return allowedDomains.contains(host)
	    }
	
	    private func fetchContent(_ url: URL) {
	        URLSession.shared.dataTask(with: url) { (data, response, error) in
	            if let error = error {
	                print("Error fetching content: \(error.localizedDescription)")
	                return
	            }
	            if let data = data, let content = String(data: data, encoding: .utf8) {
	                // Process the fetched content here
	                print("Fetched content: \(content)")
	            }
	        }.resume()
	    }
	}
	```


=== "Kotlin"
	```kotlin
	import android.content.Intent
	import android.net.Uri
	import android.os.Bundle
	import androidx.appcompat.app.AppCompatActivity
	import kotlinx.coroutines.Dispatchers
	import kotlinx.coroutines.GlobalScope
	import kotlinx.coroutines.launch
	import java.io.BufferedReader
	import java.io.InputStreamReader
	import java.net.HttpURLConnection
	import java.net.URL
	
	class MainActivity : AppCompatActivity() {
	    private val allowedDomains = listOf("example.com", "trusteddomain.com") // Add your trusted domain names here
	
	    override fun onCreate(savedInstanceState: Bundle?) {
	        super.onCreate(savedInstanceState)
	        setContentView(R.layout.activity_main)
	
	        // Get the URL from the intent
	        val intent: Intent = intent
	        val url: String? = intent.getStringExtra("url")
	
	        if (url != null) {
	            // Verify the domain name against the whitelist
	            if (isDomainAllowed(url)) {
	                // Fetch the content from the provided URL
	                GlobalScope.launch(Dispatchers.IO) {
	                    val content: String? = fetchContent(url)
	                    // Process the fetched content as needed
	                    if (content != null) {
	                        // TODO: Process the fetched content here
	                    }
	                }
	            } else {
	                // Handle unauthorized domain
	                // TODO: Implement appropriate action for unauthorized domain
	            }
	        }
	    }
	
	    private fun isDomainAllowed(urlString: String): Boolean {
	        val url = URL(urlString)
	        val domain = url.host
	        return allowedDomains.contains(domain)
	    }
	
	    private fun fetchContent(urlString: String): String? {
	        var connection: HttpURLConnection? = null
	        var reader: BufferedReader? = null
	
	        try {
	            val url = URL(urlString)
	            connection = url.openConnection() as HttpURLConnection
	            connection.requestMethod = "GET"
	
	            // Check if the response code is successful
	            if (connection.responseCode == HttpURLConnection.HTTP_OK) {
	                reader = BufferedReader(InputStreamReader(connection.inputStream))
	                val response = StringBuilder()
	                var line: String?
	
	                // Read the response line by line
	                while (reader.readLine().also { line = it } != null) {
	                    response.append(line)
	                }
	
	                return response.toString()
	            }
	        } catch (e: Exception) {
	            e.printStackTrace()
	        } finally {
	            // Close the connection and reader
	            connection?.disconnect()
	            reader?.close()
	        }
	
	        return null
	    }
	}
	```
