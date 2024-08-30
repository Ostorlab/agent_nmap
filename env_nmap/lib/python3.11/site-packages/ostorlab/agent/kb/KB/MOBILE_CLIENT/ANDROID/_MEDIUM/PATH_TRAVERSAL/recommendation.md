**Path containment:** Normalize the path and check whether it's contained within the destination directory or not. 

=== "Dart"
	```dart
	import 'package:file/local.dart';
	import 'dart:io';
	
	void main() {
	  var fileSystem = LocalFileSystem();
	  var currentDirectory = Directory.current.path;
	  print(currentDirectory);
	  var inputFile = File('$currentDirectory/../../passwords.txt');
	  var outputFile = File('$currentDirectory/pass.txt');
	
	  if (!isWithinDirectory(inputFile, currentDirectory) ||
	      !isWithinDirectory(outputFile, currentDirectory)) {
	    print("Invalid file path");
	    return;
	  }
	
	  inputFile.copy(outputFile.path)
	      .then((_) => print("File copied successfully"))
	      .catchError((error) => print("Error: $error"));
	}
	
	bool isWithinDirectory(FileSystemEntity file, String directoryPath) {
	  var fileDirectory = Directory(file.parent.path);
	  var specifiedDirectory = Directory(directoryPath);
	  return fileDirectory.path == specifiedDirectory.path ||
	      fileDirectory.path.startsWith('${specifiedDirectory.path}${Platform.pathSeparator}');
	}
	
	
	```


=== "Swift"
	```swift
	import Foundation
	
	func readSensitiveFile(fileURL: URL) -> String? {
	    let fileManager = FileManager.default
	    
	    // Check if the fileURL is within the allowed directory
	    if fileURL.pathComponents.contains("path") && fileURL.pathComponents.contains("to") && fileURL.pathComponents.contains("user") {
	        let fileContents = fileManager.contents(atPath: fileURL.path)
	        return String(data: fileContents!, encoding: .utf8)
	    }
	    
	    return nil
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
	    val sanitizedFilePath = filePath.replace("..", "").replace("/", "")
	    val file = File("/var/www/files/$sanitizedFilePath")
	    return file.readText()
	}
	
	fun main() {
	    println("Enter the file name:")
	    val fileName = readLine()
	
	    try {
	        val content = fileName?.let { readFile(it) }
	        println("File content: $content")
	    } catch (e: Exception) {
	        println("Error: ${e.message}")
	    }
	}
	```


**Absolute Path Usage:** Prefer using absolute paths instead of relative paths whenever possible. By using absolute paths, the application explicitly specifies the exact location of the file or directory, leaving no room for interpretation.

=== "Dart"
	```dart
	import 'dart:io';
	import 'package:path/path.dart' as path;
	
	void main() {
	  final absolutePath = '/path/to/file.txt';
	  var file = File(absolutePath);
	  
	  // print('File name: ${path.basename(dir.file.path)}');
	  print('File name: ${path.basename(file.path)}');
	}
	```


=== "Swift"
	```swift
	import Foundation
	
	func main() {
	    let absolutePath = "/path/to/file.txt"
	    let fileManager = FileManager.default
	
	    if fileManager.fileExists(atPath: absolutePath) {
	        // Perform operations on the file
	        print("File exists at \(absolutePath)")
	    } else {
	        print("File not found at \(absolutePath)")
	    }
	}
	
	main()
	
	```


=== "Kotlin"
	```kotlin
	import java.io.File
	
	fun main() {
	    val absolutePath = "/path/to/file.txt"
	    val file = File(absolutePath)
	
	    if (file.exists()) {
	        // Perform operations on the file
	        println("File exists at $absolutePath")
	    } else {
	        println("File not found at $absolutePath")
	    }
	}
	
	```