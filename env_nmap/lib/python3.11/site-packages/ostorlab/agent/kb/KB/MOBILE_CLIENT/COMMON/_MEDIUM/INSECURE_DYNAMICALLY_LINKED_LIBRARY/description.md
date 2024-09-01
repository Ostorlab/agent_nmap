Dynamic loading of libraries, when not implemented securely, can introduce a range of significant vulnerabilities that pose serious risks to the security and integrity of an application:

**Insecure Loading Path**: This vulnerability arises when an application loads libraries from untrusted or manipulated locations. If an application unwittingly loads libraries from malicious sources, it opens the door to potential attacks. Attackers can exploit this weakness by placing malicious libraries in untrusted locations, leading to code execution with elevated privileges or unauthorized access to sensitive resources.

**Library Hijacking**: Library hijacking occurs when an attacker substitutes a legitimate library with a malicious one. By tampering with the library loading process, the attacker can deceive the application into loading the malicious library instead. This can enable a wide range of attacks, including code injection, privilege escalation, and unauthorized access to sensitive data.

These vulnerabilities, if left unaddressed, can have severe consequences. Attackers can inject malicious code into an application, compromise its integrity, gain unauthorized access to critical resources, and potentially exploit other security vulnerabilities.

Examples of vulnerable implementations:


=== "Dart"
	```dart
	void loadDependency(String unsanitized_user_input) {
	  // Dynamically load the library without sanitizing the input
	  final dylib = DynamicLibrary.open(unsanitized_user_input);
	
	  // Resolve and call a function from the loaded library that contains malicous code
	  final libraryMethod =
	      dylib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>(
	          'getSensitiveData');
	  final result = libraryMethod();
	}
	
	```


=== "Swift"
	```swift
	func loadDynamicLibrary(unsanitized_user_input: String) {
	
	    // Attempt to dynamically load the library without sanitizing user input 
	    if let libraryHandle = dlopen(unsanitized_user_input, RTLD_NOW) {
	        // Library loaded successfully, resolve a function that could contain malicous code
	        if let method = dlsym(libraryHandle, "libraryMethod") {
	            typealias FunctionType = @convention(c) () -> String
	            let function = unsafeBitCast(libraryMethod, to: FunctionType.self)
	            let result = function()
	        }
	        dlclose(libraryHandle)
	    }
	}
	```

=== "Kotlin"
	```kotlin
	fun loadDependency(unsanitized_user_input : String) {
	
	    // Load the library dynamically without sanitizing the input
	    System.load(unsanitized_user_input)
	
	    // Perform some operation using the dynamically loaded library
	    val result = libraryMethod()
	}
	
	```

