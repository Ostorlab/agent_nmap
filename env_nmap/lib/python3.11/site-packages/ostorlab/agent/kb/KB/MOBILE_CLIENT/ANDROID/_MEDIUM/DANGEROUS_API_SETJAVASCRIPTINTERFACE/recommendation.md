This issue has been resolved in applications developed for Android 4.2 (API level 17) and above. Starting from Android 4.2 (API level 17) and above, only methods explicitly marked with the @JavascriptInterface annotation are available to JavaScript code within the WebView. The @JavascriptInterface annotation must be added to any method that is intended to be exposed via the native bridge (the method must also be public). An example is presented below:

=== "Java"
	```java
	    @JavascriptInterfacepublic void method() {dostuff();}
	```


To resolve the issue, you need to build you application for API 17 or above and redistribute it. The users would need to upgrade their applications to use the new non-vulnerable application.