The application is programmatically preventing screenshots, which prevents the Monkey Tester (Ostorlab's automated mobile crawler) from computing coverage.

Android applications can programmatically block taking screenshots:

* Use the `FLAG_SECURE` window flag:

By setting the `FLAG_SECURE` window flag, you can prevent the content of your app's window from appearing in screenshots or from being viewed on non-secure displays.

To set the `FLAG_SECURE` window flag, you can call `setFlags()` on your Window object and pass in the `FLAG_SECURE` flag. For example:

=== "Java"
	```java
	getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
	                     WindowManager.LayoutParams.FLAG_SECURE);
	```


Note that this will also prevent the content of your app's window from being recorded by screen recording apps.

* Use the `MediaProjection` API:

The `MediaProjection` API allows you to capture the content of the device's screen in real-time. By using this API, you can programmatically block taking screenshots by simply not starting the screen capture session when the user attempts to take a screenshot.

To use the `MediaProjection` API, you will need to request the `CAPTURE_SCREENSHOT` or `CAPTURE_VIDEO_OUTPUT` permission, depending on your use case. You can then create a MediaProjection object and call `start()` to begin the screen capture session.

=== "Java"
	```java
	MediaProjectionManager mediaProjectionManager =
	        (MediaProjectionManager) getSystemService(Context.MEDIA_PROJECTION_SERVICE);
	
	Intent permissionIntent = mediaProjectionManager.createScreenCaptureIntent();
	startActivityForResult(permissionIntent, REQUEST_SCREENSHOT);
	
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
	    if (requestCode == REQUEST_SCREENSHOT) {
	        if (resultCode == RESULT_OK) {
	            // Start the screen capture session
	            MediaProjection mediaProjection = mediaProjectionManager.getMediaProjection(resultCode, data);
	            mediaProjection.start();
	        }
	    }
	}
	```


You can then stop the screen capture session by calling `stop()` on the `MediaProjection` object.

* Use the `MediaProjectionManager` API:

The `MediaProjectionManager` API provides a system service that allows you to manage screen capture sessions. You can use this API to programmatically block taking screenshots by checking if a screen capture session is active before allowing the user to take a screenshot.

To use the `MediaProjectionManager` API, you can call `isProjectionActive()` to check if a screen capture session is currently active. If a screen capture session is active, you can prevent the user from taking a screenshot.

=== "Java"
	```java
	MediaProjectionManager mediaProjectionManager =
	        (MediaProjectionManager) getSystemService(Context.MEDIA_PROJECTION_SERVICE);
	
	if (mediaProjectionManager.isProjectionActive()) {
	    // A screen capture session is active, so prevent the user from taking a screenshot
	} else {
	    // A screen capture session is not active, so allow the user to take a screenshot
	}
	```

