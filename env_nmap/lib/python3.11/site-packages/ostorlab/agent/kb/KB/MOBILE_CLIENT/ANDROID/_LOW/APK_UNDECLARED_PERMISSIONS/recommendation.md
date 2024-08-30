Before you declare permissions in your app, consider whether you need the permission in the first place, or if the there is an alternative way to support the functionality in your app.

1. Declare a permission in the manifest file:

  Before applying a permission on any component, make sure it is declared using `<permission>` element.

  For example, an app that wants to control who can start one of its activities could declare a permission for this operation as follows:

  * Step 1 : I declare a permission with the name `com.example.myapp.permission.DEADLY_ACTIVITY` and fill the necessary attributes
  * Step 2: I apply the permission `com.example.myapp.permission.DEADLY_ACTIVITY` on my activity


=== "XML"
	```xml
	
	<manifest
	        xmlns:android="http://schemas.android.com/apk/res/android"
	        package="com.example.myapp">
	
	    <permission
	            android:name="com.example.myapp.permission.DEADLY_ACTIVITY"
	            android:label="@string/permlab_deadlyActivity"
	            android:description="@string/permdesc_deadlyActivity"
	            android:permissionGroup="android.permission-group.COST_MONEY"
	            android:protectionLevel="dangerous"/>
	    ...
	    <activity android:exported="true" android:name="com.important.PushActivity"
	              android:permission="com.example.myapp.permission.DEADLY_ACTIVITY"/>
	
	</manifest>
	```



2. Only use the minimum set of permissions necessary for your app's functionality. This can be achieved by reviewing your app's code and identifying the specific resources or data that the app requires to function properly.
   For each permission that your app requests, make sure that it offers clear benefits to users and that the request is done in a way that's obvious to them.
   
3. Use lint checks in Android Studio to detect and prevent undeclared permissions. Lint is a tool built into Android Studio that analyzes an app's code and resources to identify potential problems, including undeclared permissions. Lint can be run by selecting "Analyze" -> "Run Inspection by Name" -> "Missing Permissions" in Android Studio.
   
4. Analyze app permissions using tools like APK Analyzer. APK Analyzer is a tool built into Android Studio that allows developers to inspect the contents of an APK file, including its permissions, activities, services, and other components. Developers can also use security-focused testing frameworks like Appium, Selendroid, and Robotium to detect and prevent security vulnerabilities, including undeclared permissions.
   
5. Consider your application's dependencies: When you include a library, you also inherit its permission requirements. Be aware of the permissions that each dependency requires and what those permissions are used for.
