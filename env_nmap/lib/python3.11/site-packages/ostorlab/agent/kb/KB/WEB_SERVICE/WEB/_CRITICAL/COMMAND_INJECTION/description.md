Command injection is a security breach that allows unauthorized execution of commands within a server's operating system. It occurs when an application inadvertently transfers unverified user inputs (from forms, cookies, HTTP headers, etc.) directly to the system shell. This enables attackers to execute their own commands, typically with the same permissions as the vulnerable application. Command injection attacks are possible largely due to insufficient input validation.

### Examples

#### Java

```java
String userInput = request.getParameter("input");
Runtime.getRuntime().exec("ls " + userInput);
```

#### Javascript

```javascript
const userInput = req.body.input;
const exec = require('child_process').exec;
exec('ls ' + userInput, (error, stdout, stderr) => {
  console.log(stdout);
});
```

#### Php

```php
$userInput = $_GET['input'];
system('ls ' . $userInput);
```

