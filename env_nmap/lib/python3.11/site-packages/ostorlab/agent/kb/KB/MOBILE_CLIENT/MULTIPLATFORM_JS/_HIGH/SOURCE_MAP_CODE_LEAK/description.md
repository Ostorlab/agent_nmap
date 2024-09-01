The application should provide as little explanatory information as possible with the compiled code. Metadata such as debugging information, line numbers, and descriptive function or method names make the binary or byte-code easier to reverse engineer.

The application leaks the source code through source map files used solely for debugging and development.

Source code can be fully retrieved with the following sample script:

=== "Python"
	```python
	
	import sys
	import json
	import os
	
	filename = sys.argv[1]
	
	map = json.load(open(filename, 'r'))
	
	files = map['sources']
	content = map['sourcesContent']
	
	if len(files) != len(content):
	    raise ValueError('not same lengths')
	
	for f, c in zip(files, content):
	    f = f.replace('../', '')
	    print(f)
	    if '/' in f:
	        os.makedirs(os.path.dirname(f), exist_ok=True)
	    with open(f, 'w') as o:
	        o.write(c)
	```



Leaking source code can help attackers easily forge malicious applications or understand the internals of the application to identify vulnerabilities.