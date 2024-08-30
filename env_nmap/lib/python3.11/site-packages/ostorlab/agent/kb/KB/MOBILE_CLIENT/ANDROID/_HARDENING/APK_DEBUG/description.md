The `android:debuggable` attribute in the `Application` that is defined in the Android Manifest determines whether the application can be debugged.

Debug mode allows attackers to access the application filesystem and attach a debugger and access sensitive data or perform malicious actions.

The following steps can be used to start a debug session using `jdb`:

* Use `adb jdwp` to identify the `PID` of the target application:

```bash
$adb jdwp
3466
15446
```

* Create a communication channel using `adb` and attach to it using `jdb`:

```bash
$adb forward tcp:7777 jdwp:$(adb shell ps | grep "package-id")
$jdb -attach localhost:7777
```

* Access the application filesystem:

```bash
$adb shell
$run-as package-id
$...insert malicious action...
```  

An attacker can debug the application without access to source code and leverage it to perform malicious actions on behalf of the user, modify the application behavior or access sensitive data like credentials and session cookies.