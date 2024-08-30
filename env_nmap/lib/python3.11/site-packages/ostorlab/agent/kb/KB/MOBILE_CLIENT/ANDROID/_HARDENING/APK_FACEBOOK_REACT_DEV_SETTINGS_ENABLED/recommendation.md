Disable `com.facebook.react.devsupport.DevSettingsActivity` in `AndroidManifest.xml` before deploying your app to the public.

=== "XML"
	```xml
	<activity android:name="com.facebook.react.devsupport.DevSettingsActivity"
	      android:exported="false"/>
	```

