Insecure storage of password could lead to account compromise. The vulnerability is the result of storing password using
insecure methods that are susceptible to unauthorized access or compromise.

The following example shows insecure storage of password credentials in cookies:

=== "Javascript"
	```javascript
	response.addCookie(new Cookie("password", password));
	```
