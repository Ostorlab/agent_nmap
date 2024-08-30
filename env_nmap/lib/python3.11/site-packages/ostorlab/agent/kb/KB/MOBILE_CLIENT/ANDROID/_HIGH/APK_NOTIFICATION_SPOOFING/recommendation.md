To prevent unauthorized notifications, ensure the following protections are implemented:

* Notification handling services and activities should be restricted with proper permissions and not be exported/browsable unless necessary.
* Ensure the permissions are set with secure protection levels appropriate to the application context


For example, if the notification handler activity is `com.adobe.phonegap.push.PushHandlerActivity`:

=== "AndroidManifest.xml"
	```xml
	<activity android:name="com.adobe.phonegap.push.PushHandlerActivity"
	      android:exported="false"/>
	```
