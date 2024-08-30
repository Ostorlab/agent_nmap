Applications can expose their functionality to other apps by defining permissions which those other apps can request.

To enforce your own permission, you must first declare it in your `AndroidManifest.xml` using `<permission>` element before applying it to your components using `android:permission=`

If the application applies a permission without declaring it, a malicious app can declare that permission with a `normal` protection level, request it and invoke the protected component of your application.

In addition, undeclared permissions can be a security risk, as the user may not be aware that the app is accessing sensitive data or system resources. This could lead to privacy violations or other security issues, such as an app accessing the user's location without their consent.



