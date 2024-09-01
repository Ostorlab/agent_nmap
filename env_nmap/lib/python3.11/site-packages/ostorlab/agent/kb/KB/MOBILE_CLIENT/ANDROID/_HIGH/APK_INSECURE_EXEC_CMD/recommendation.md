To mitigate the command injection vulnerability, here are some recommendations:
 
- Whenever possible, avoid constructing system commands from user input.
- Use parameterized queries to pass parameters to a query or command string in a secure manner.
- Use input validation to ensure user-supplied data is sanitized and contains only expected values.


Below are code examples where we use parametrized queries to execute system commands rather than raw concatenation.

=== "Kotlin"
	```kotlin
	val cmd = listOf("ls", "-al", "/path/to/directory")
	val pb = ProcessBuilder(cmd)
	val process = pb.start()
	```


=== "Dart"
	```dart
	ProcessResult result = await Process.run(
	      "ls",
	      ['-al', '/path/to/directory'],
	      includeParentEnvironment: false,
	      environment: {});
	```

