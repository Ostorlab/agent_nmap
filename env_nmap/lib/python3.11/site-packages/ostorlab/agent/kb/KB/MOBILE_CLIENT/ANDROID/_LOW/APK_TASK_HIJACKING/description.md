An Android task is a collection of activities that users interact with when performing a certain job. Activities from
different apps can reside in the same task which might be used to relocate a malicious activity to your application's task by
manipulating the following parameters:

* __Task Affinity__ controlled by attribute `taskAffinity`
* __Task Reparenting__ controlled by attribute `allowTaskReparenting`

Task Affinity is an activity attribute defined in the `<activity>` tag in the `AndroidManifest.xml` file.
Task Affinity specifies which task that the activity desires to join. By default, all activities in an app have the
same affinity, which is the app package name.


=== "XML"
	```xml
	
	<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="co.secureApp.app">
	    <application>
	        <activity android:name=".ActivityA"></activity>
	        <activity android:name=".ActivityB" android:taskAffinity="co.ostorlab.Myapp:taskB"></activity>
	    </application>
	</manifest>
	```



`allowTaskReparenting` when set to `true` for an activity A, and when a new task with the same affinity is brought to
the front, the system moves the __relocatable__ activity A from its original hosting task to the new foreground task stack.

Task Hijacking attacks come in different flavors:

* __Task Affinity Control__: application has a package name `com.mySecureApp.app` and activity __A1__. A malicious
  application has two activities __M1__ and __M2__ where `M2.taskAffinity = com.mySecureApp.app`
  and `M2.allowTaskReparenting = true`. If the malicious app is open on __M2__, once you start your application, __M2__ is relocated to the front and the user
  will interact with the malicious application.

* __Single Task Mode__: the application has set launch mode to `singleTask`. A malicious application
  with `M2.taskAffinity = com.mySecureApp.app` can hijack the target application task stack.

* __Task Reparenting__: application has set `taskReparenting` to `true`. A malicious application can move the target
  application task to the malicious application stack.

Task hijacking can be used to perform phishing, denial of use attack, and has been exploited in the past by banking
malware trojans. New flavors of the attacks (StandHogg 2.0) are extremely hard to detect, as they are code-based attacks.

Task hijacking has been addressed in Android version 11 as a part of a fix of `CVE-2020-0267` `WindowManager` confused
deputy.