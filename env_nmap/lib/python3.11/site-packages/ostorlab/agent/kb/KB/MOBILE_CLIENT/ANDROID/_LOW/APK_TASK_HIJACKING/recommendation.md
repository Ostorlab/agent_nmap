Different forms of Task Hijacking vulnerabilities require different fixes:

* Set the task affinity of the application activities to `""`(empty string) in the `<activity>` tag of the `AndroidManifest.xml` to force the activities to use a randomly generated task affinity, or set it at the`<application>` tag to enforce on all activities in the application.

OR

* Set the `android:launchMode` to `singleInstance`. `singleInstance` ensure that no other activities will be created in the same task.

* Do not specify launch mode set to `singleTask` or add support for a monitoring service to detect the presence of malicious foreground tasks.

* Do not set the flag `FLAG_ACTIVITY_NEW_TASK` in activity launch intents, or use with the `FLAG_ACTIVITY_CLEAR_TASK`:

=== "Java"
	```java
	Intent i = new Intent(this, AnActivity.class);
	i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
	i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);
	startActivity(i);
	```



* Do not specify `allowReparenting` with `taskAffinity` or add support a monitoring service to detect the presence of malicious foreground tasks.

* Prefer the use of Explicit intent, which specify which application will satisfy the intent, by supplying the target application package name or a fully-qualified component class name. Implicit intent only specifies the general action.
