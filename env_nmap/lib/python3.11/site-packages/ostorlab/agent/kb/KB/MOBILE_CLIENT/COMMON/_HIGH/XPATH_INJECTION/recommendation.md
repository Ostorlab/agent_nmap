To mitigate XPath Injection vulnerabilities, it is important to: 

* Use parameterized queries or prepared statements, which separate the user input from the query logic.
* Properly validate and sanitize user input before using it in XPath queries. 

=== "Dart"
	```dart
	
	bool _validate_query(String _searchQuery){
	  // check for special characters
	  for(var i = 0; i < tokens.length; i++){
	      if (string.contains(new RegExp(r'[A-Z]')) == false){
	        return false;
	      }
	    }
	  return true;
	}
	
	void _fetch_data(String _searchQuery) {
	  
	  // validate user input
	  if (_validate_query(_searchQuery) == false){
	    // raise error
	    return ;
	  }
	  final content = XmlDocument.parse(xmlFileContent);
	  final xml_node = XmlXPath.node(content);
	  final xpath = xml_node.query('//book[author=$_searchQuery');
	
	  showDialog(
	    context: context,
	    builder: (context) => AlertDialog(
	      title: Text('Search Result'),
	      content: Text(result),
	    ),
	  );
	  }
	```


=== "Swift"
	```swift
	import Foundation
	import SWXMLHash
	
	func main() {
	    print("Enter search term:")
	    guard let searchTerm = readLine()?.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
	        print("Invalid search term")
	        return
	    }
	    
	    let xml = SWXMLHash.parse(xmlString)
	    let results = xml["books"]["book"].all(withAttribute: "title", matchingXPath: "//title[contains(text(), '\(searchTerm)')]")
	    
	    for result in results {
	        print(result["title"].element!.text)
	        print(result["author"].element!.text)
	    }
	}
	```


=== "Kotlin"
	```kotlin
	
	fun sanitize(input: String): String {
	    // Replace all XPath special characters with their HTML entities
	    return input.replace("&", "&amp;")
	                .replace("<", "&lt;")
	                .replace(">", "&gt;")
	                .replace(""", "&quot;")
	                .replace("'", "&apos;")
	}
	
	fun main() {
	    val userInput = readLine() ?: return
	
	    val xmlData = """
	        <users>
	            <user>
	                <username>Alice</username>
	                <password>pass123</password>
	            </user>
	            <user>
	                <username>Bob</username>
	                <password>pass456</password>
	            </user>
	        </users>
	    """.trimIndent()
	
	    val sanitizedInput = sanitize(userInput)
	    val xpathQuery = "//*[username/text()='${sanitizedInput}']"
	
	    val xpath = XPathFactory.newInstance().newXPath()
	    val expression = xpath.compile(xpathQuery)
	
	    val result = expression.evaluate(xmlData, XPathConstants.NODESET)
	
	    val nodeList = result as? List<*> ?: emptyList<Any>()
	
	    val matchedUsers = nodeList.filterIsInstance<org.w3c.dom.Node>()
	        .map { node -> node.textContent }
	        .joinToString(", ")
	
	    println("Matched users: $matchedUsers")
	}
	```
