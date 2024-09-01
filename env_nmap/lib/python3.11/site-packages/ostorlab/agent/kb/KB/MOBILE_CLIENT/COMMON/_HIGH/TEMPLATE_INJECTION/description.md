Template Injection is a vulnerability that allows an attacker to inject malicious code into a template-rendered text, which can then be executed by the server. This can lead to a range of attacks, including data theft, privilege escalation, and remote code execution. Template Injection attacks are particularly dangerous because they can be difficult to detect and can offer dangerous capabilities to an attacker.


Here, the code is vulnerable because we're creating the template string using direct concatenation from the user input (userName), allowing the user to control the structure of the template. This can lead to template injection if the user provides a string that contains Mustache template tags.

=== "Dart"
	```dart
	import 'dart:io';
	import 'package:mustache_template/mustache_template.dart';
	
	Future main() async {
	  var server = await HttpServer.bind(
	    InternetAddress.loopbackIPv4,
	    8080,
	  );
	  print('Listening on localhost:${server.port}');
	
	  await for (HttpRequest request in server) {
	    final userName = request.uri.queryParameters['name'] ?? 'guest';
	    // Vulnerable to template injection due to template string concatenation
	    final template = 'Hello, ${userName}';
	    final output = Template(template, lenient: true, htmlEscapeValues: false)
	        .renderString({});
	    request.response
	      ..write(output)
	      ..close();
	  }
	}
	```


=== "Kotlin"
	```kotlin
	import com.github.mustachejava.DefaultMustacheFactory
	import com.github.mustachejava.Mustache
	import io.ktor.application.*
	import io.ktor.request.*
	import io.ktor.response.*
	import io.ktor.routing.*
	import io.ktor.server.engine.*
	import io.ktor.server.netty.*
	import io.ktor.http.Parameters
	
	fun main() {
	    embeddedServer(Netty, port = 8080) {
	        routing {
	            get("/") {
	                val parameters: Parameters = call.request.queryParameters
	                val userName = parameters["name"] ?: "guest"
	
	                // Vulnerable to template injection due to template string concatenation
	                val mf = DefaultMustacheFactory()
	                val mustache: Mustache = mf.compile("template", "Hello, $userName")
	                
	                val writer = StringWriter()
	                mustache.execute(writer, emptyMap<String, Any>())
	                writer.flush()
	
	                call.respondText(writer.toString())
	            }
	        }
	    }.start(wait = true)
	}
	```

