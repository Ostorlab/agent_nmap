Set `setWebContentsDebuggingEnabled` to `false` or only set it to `true` if the app is in debug mode.

Example:

=== "Java"
	```java
	    if (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE)) {
        WebView.setWebContentsDebuggingEnabled(true);
      }
	```
