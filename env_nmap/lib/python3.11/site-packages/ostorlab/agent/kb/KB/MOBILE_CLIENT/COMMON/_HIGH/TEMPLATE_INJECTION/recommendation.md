To mitigate this vulnerability, it is important to ensure that all user input is properly sanitized and validated before
being passed to the server-side template engine. 

Template engine will typically have a `render` method that takes a context that will be safely embedded in the text.

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
	    final template = 'Hello, {{ username }}';
	    final output = Template(template, lenient: true, htmlEscapeValues: false)
	        .renderString({'username': username});
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
	import java.io.StringWriter
	
	fun main() {
	    embeddedServer(Netty, port = 8080) {
	        routing {
	            get("/") {
	                val parameters: Parameters = call.request.queryParameters
	                val userName = parameters["name"] ?: "guest"
	
	                // Use a predefined template and pass untrusted data as values
	                val mf = DefaultMustacheFactory()
	                val mustache: Mustache = mf.compile("template", "Hello, {{name}}")
	                
	                val writer = StringWriter()
	                mustache.execute(writer, mapOf("name" to userName))
	                writer.flush()
	
	                call.respondText(writer.toString())
	            }
	        }
	    }.start(wait = true)
	}
	
	```
