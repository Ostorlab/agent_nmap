Explicitly set the attribute `android:usesCleartextTraffic` value to `false` and define an Android Network Security Config.

The default value for apps that target API level 27 or lower is `true`. Apps that target API level 28 or higher default to `false`.

=== "XML"
	```xml
	<application android:icon="@drawable/icon" android:usesCleartextTraffic="false">
	```

