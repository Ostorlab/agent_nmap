The application is compiled with debug mode disabled. Debug mode allows attackers to access the application filesystem
and attach a debugger to access sensitive data or perform malicious actions.

For instance attach a Java (JDWP) debugger:

```bash
$adb forward tcp:7777 jdwp:$(adb shell ps | grep "package-id")
$jdb -attach localhost:7777
```

To access the applicatin filesystem:

```bash
$adb shell
$run-as package-id
$...insert malicious action...
```  

Attacker can debug the application without access to source code and leverage it to perform malicious actions on behalf
ot the user, modify the application behavior or access sensitive data like credentials and session cookies.
