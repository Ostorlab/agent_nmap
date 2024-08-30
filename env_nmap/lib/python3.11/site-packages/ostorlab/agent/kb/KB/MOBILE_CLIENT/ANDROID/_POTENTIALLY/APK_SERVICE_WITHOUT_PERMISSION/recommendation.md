`service` can expose several methods to external components. It is possible to define arbitrary permissions for each
method using the method `checkPermission`.

It is also possible to separate services and restrict access by enforcing permissions in the manifest's `<service>` tag.

=== "XML"
	```xml
	
	<permission android:name="co.ostorlab.custom_permission" android:label="custom_permission"
	            android:protectionLevel="dangerous"></permission>
	
	<service android:name="co.ostorlab.custom_service" android:permission="co.ostorlab.custom_permission">
	<intent-filter>
	    <action android:name="co.ostorlab.ACTION"/>
	</intent-filter>
	</service>
	```


The service can enforce permissions on individual IPC calls by calling the method `checkCallingPermission`before
executing the implementation of that call.