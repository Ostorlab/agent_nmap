An application can allow an attacker to navigate through the file system beyond the intended 
boundaries. This can lead to unauthorized access to sensitive files or directories. 
By manipulating file paths, an attacker can bypass access controls and retrieve or modify critical data, 
such as configuration files, user credentials, or confidential documents. This vulnerability poses 
a significant threat as it enables the attacker to escalate privileges, execute arbitrary code, 
or launch further attacks on the system.


=== "Dart"
	```dart
	import 'package:file/local.dart';
	
	void main() {
	  var file = new LocalFileSystem();
	  var f = file.file("../../passwords.txt");
	  f.copy("pass.txt");
	}
	
	// Or changing the root of the current running process:
	
	import 'package:file/file.dart';
	import 'package:file/chroot.dart';
	import 'package:file/local.dart';
	import 'package:path/path.dart' as path;
	
	void main() {
	  final String root = path.canonicalize("../../..");
	  final FileSystem newRoot = new ChrootFileSystem(
	  const LocalFileSystem(),
	  root,
	);
	```


=== "Swift"
	```swift
	import Foundation
	
	func readSensitiveFile(fileURL: URL) -> String? {
	    let fileManager = FileManager.default
	    let fileContents = fileManager.contents(atPath: fileURL.path)
	    
	    return String(data: fileContents!, encoding: .utf8)
	}
	
	func main() {
	    let userDirectory = FileManager.default.homeDirectoryForCurrentUser
	    let userInput = "/path/to/user/input.txt"
	    let fileURL = userDirectory.appendingPathComponent(userInput)
	    
	    if let contents = readSensitiveFile(fileURL: fileURL) {
	        print("File contents: \(contents)")
	    } else {
	        print("Failed to read file.")
	    }
	}
	
	main()
	
	```


=== "Kotlin"
	```kotlin
	import java.io.File
	
	fun readFile(filePath: String): String {
	    val file = File("/var/www/files/$filePath")
	    return file.readText()
	}
	
	fun main() {
	    println("Enter the file name:")
	    val fileName = readLine()
	
	    try {
	        val content = readFile(fileName!!)
	        println("File content: $content")
	    } catch (e: Exception) {
	        println("Error: ${e.message}")
	    }
	}
	```

