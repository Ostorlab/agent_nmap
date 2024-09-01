In your app manifest file, set the attribute `android:allowBackup` to enable or disable backup. The default value is
true but to make your intentions clear, it is recommended to explicitly set the attribute in the application's manifest
as shown below:

=== "XML"
	```xml
	    <manifest>
	        <application android:allowBackup="true">
	        </application>
	    </manifest>
	```


If the application contains sensitive data that you don't want to be backed up or restored, you can disable backup mode
by setting the attribute `android:allowBackup` to false as shown below:

=== "XML"
	```xml
	    <manifest>
	        <application android:allowBackup="false">
	        </application>
	    </manifest>
	```
