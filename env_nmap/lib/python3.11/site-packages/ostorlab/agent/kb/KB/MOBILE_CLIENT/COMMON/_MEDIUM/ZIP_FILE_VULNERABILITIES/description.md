ZIP files, which are compressed archives used to store and transmit multiple files, are a widely adopted file format due to their convenience and compatibility across different platforms. However, like any digital file format, ZIP files are not immune to vulnerabilities. Here are some common vulnerabilities associated with ZIP files:

### Path Traversal 

Path traversal, also known as directory traversal or directory climbing, is a vulnerability that allows an attacker to access files or directories outside of the intended extraction directory. When extracting a ZIP file, if the extraction process does not properly validate the file paths within the archive, an attacker can craft a malicious ZIP file containing special characters or sequences that enable them to traverse directories and access sensitive files on the system. This can lead to unauthorized disclosure of sensitive information or even remote code execution.

=== "Dart"
	```dart
	import 'dart:io';
	import 'archive/archive.dart';
	
	void extractZipFile(String path) {
	  File file = File(path);
	  Archive archive = ZipDecoder().decodeBytes(file.readAsBytesSync());
	
	  for (ArchiveFile archiveFile in archive) {
	    // Insecure: Does not properly validate file paths
	    File extractedFile = File('/tmp/' + archiveFile.name);
	    extractedFile.createSync(recursive: true);
	    extractedFile.writeAsBytesSync(archiveFile.content);
	  }
	}
	```


=== "Swift"
	```swift
	import Foundation
	import ZIPFoundation
	
	func extractZipFile(path: String) {
	    guard let archive = Archive(url: URL(fileURLWithPath: path), accessMode: .read) else {
	        return
	    }
	
	    for entry in archive {
	        // Insecure: Does not properly validate file paths
	        let extractedFilePath = "/tmp/\(entry.path)"
	        let extractedFileURL = URL(fileURLWithPath: extractedFilePath)
	        
	        do {
	            try FileManager.default.createDirectory(atPath: extractedFileURL.deletingLastPathComponent().path,
	                                                    withIntermediateDirectories: true,
	                                                    attributes: nil)
	            try archive.extract(entry, to: extractedFileURL)
	        } catch {
	            print("Extraction failed: \(error.localizedDescription)")
	        }
	    }
	}
	```


=== "Kotlin"
	```kotlin
	import java.io.File
	import java.util.zip.ZipInputStream
	
	fun extractZipFile(path: String) {
	    val file = File(path)
	    val zipInputStream = ZipInputStream(file.inputStream())
	
	    var entry = zipInputStream.nextEntry
	    while (entry != null) {
	        // Insecure: Does not properly validate file paths
	        val extractedFile = File("/tmp/" + entry.name)
	        extractedFile.parentFile.mkdirs()
	        extractedFile.outputStream().use { output ->
	            zipInputStream.copyTo(output)
	        }
	
	        entry = zipInputStream.nextEntry
	    }
	
	    zipInputStream.close()
	}
	```




### Zip Symbolic Link

Symbolic links, or symlinks, are pointers to files or directories that can be used to create shortcuts or references. However, if a ZIP file extraction process does not handle symbolic links properly, an attacker can craft a malicious ZIP file that includes symbolic links pointing to sensitive files or directories on the target system. Upon extraction, these symbolic links can be followed, leading to unauthorized access to critical files or directories.


=== "Dart"
	```dart
	import 'dart:io';
	import 'archive/archive.dart';
	
	void extractZipFile(String path) {
	  File file = File(path);
	  Archive archive = ZipDecoder().decodeBytes(file.readAsBytesSync());
	
	  for (ArchiveFile archiveFile in archive) {
	    // Insecure: Does not handle symbolic links properly
	    if (archiveFile.isSymbolicLink) {
	      File symlink = File('/tmp/' + archiveFile.name);
	      symlink.createSync(recursive: true);
	      symlink.writeAsStringSync(archiveFile.content);
	    } else {
	      File extractedFile = File('/tmp/' + archiveFile.name);
	      extractedFile.createSync(recursive: true);
	      extractedFile.writeAsBytesSync(archiveFile.content);
	    }
	  }
	}
	```



=== "Swift"
	```swift
	import Foundation
	import ZIPFoundation
	
	func extractZipFile(path: String) {
	    guard let archive = Archive(url: URL(fileURLWithPath: path), accessMode: .read) else {
	        return
	    }
	
	    for entry in archive {
	        // Insecure: Does not handle symbolic links properly
	        let extractedFilePath = "/tmp/\(entry.path)"
	        let extractedFileURL = URL(fileURLWithPath: extractedFilePath)
	        
	        if entry.type == .symbolicLink {
	            do {
	                try FileManager.default.createSymbolicLink(at: extractedFileURL, withDestinationURL: entry.destinationURL)
	            } catch {
	                print("Symbolic link creation failed: \(error.localizedDescription)")
	            }
	        } else {
	            do {
	                try FileManager.default.createDirectory(atPath: extractedFileURL.deletingLastPathComponent().path,
	                                                        withIntermediateDirectories: true,
	                                                        attributes: nil)
	                try archive.extract(entry, to: extractedFileURL)
	            } catch {
	                print("Extraction failed: \(error.localizedDescription)")
	            }
	        }
	    }
	}
	```


=== "Kotlin"
	```kotlin
	import java.io.File
	import java.nio.file.Files
	import java.nio.file.Path
	import java.util.zip.ZipInputStream
	
	fun extractZipFile(path: String) {
	    val file = File(path)
	    val zipInputStream = ZipInputStream(file.inputStream())
	
	    var entry = zipInputStream.nextEntry
	    while (entry != null) {
	        // Insecure: Does not handle symbolic links properly
	        val extractedFile = File("/tmp/" + entry.name)
	        if (entry.isSymbolicLink) {
	            Files.createSymbolicLink(Path.of(extractedFile.path), Path.of(entry.link))
	        } else {
	            extractedFile.parentFile.mkdirs()
	            extractedFile.outputStream().use { output ->
	                zipInputStream.copyTo(output)
	            }
	        }
	
	        entry = zipInputStream.nextEntry
	    }
	
	    zipInputStream.close()
	}
	```



### Zip Extension Spoofing

Zip extension spoofing is a technique where an attacker spoofs the extension of a malicious file within a ZIP file to deceive users and security systems. By manipulating the ZIP file headers, the attacker can change the extension of the file within the archive to seem harmless. However, when the user extracts the file or opens it with a vulnerable application, the malicious payload is executed, potentially leading to unauthorized code execution, malware infection, or other malicious activities.

=== "Dart"
	```dart
	import 'dart:io';
	import 'archive/archive.dart';
	
	void extractZipFile(String path) {
	  File file = File(path);
	  Archive archive = ZipDecoder().decodeBytes(file.readAsBytesSync());
	
	  for (ArchiveFile archiveFile in archive) {
	    // Insecure: the zip decoder parses the filename from the Local File Header which can be manipulated
	    // Zipdecoder has to check against the central directory to make sure the extension was not altered
	    String extractedFilePath = '/tmp/' + archiveFile.name;
	    if (archiveFile.name.endsWith('.zip')) {
	      // Extracting a ZIP file within a ZIP file
	      extractZipFile(extractedFilePath);
	    } else {
	      File extractedFile = File(extractedFilePath);
	      extractedFile.createSync(recursive: true);
	      extractedFile.writeAsBytesSync(archiveFile.content);
	    }
	  }
	}
	```



=== "Kotlin"
	```kotlin
	import java.io.File
	import java.util.zip.ZipInputStream
	
	fun extractZipFile(path: String) {
	    val file = File(path)
	    val zipInputStream = ZipInputStream(file.inputStream())
	
	    var entry = zipInputStream.nextEntry
	    while (entry != null) {
	        // Insecure: the zip decoder parses the filename from the Local File Header which can be altered
	        // Zipdecoder has to check against the central directory to make sure the extension was not altered
	        val extractedFile = File("/tmp/" + entry.name)
	        if (entry.name.endsWith(".zip")) {
	            // Extracting a ZIP file within a ZIP file
	            extractZipFile(extractedFile.path)
	        } else {
	            extractedFile.parentFile.mkdirs()
	            extractedFile.outputStream().use { output ->
	                zipInputStream.copyTo(output)
	            }
	        }
	
	        entry = zipInputStream.nextEntry
	    }
	
	    zipInputStream.close()
	}
	```

