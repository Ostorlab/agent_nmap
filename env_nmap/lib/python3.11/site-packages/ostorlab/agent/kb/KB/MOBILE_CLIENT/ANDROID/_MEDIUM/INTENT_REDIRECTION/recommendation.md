As a rule of thumb, it's best to avoid exposing functionality related to redirecting nested intents. However, if the situation demands, use the following strategies for mitigation:

- Check where the intent is being redirected.
- Use PendingIntent objects. This prevents your component from being exported and makes the target action intent immutable.
- Use [IntentSanitizer](https://developer.android.com/reference/kotlin/androidx/core/content/IntentSanitizer) to make a sanitized copy of an Intent

=== "Java"
	```java
	import android.content.Intent;
	import android.os.Bundle;
	import android.support.v7.app.AppCompatActivity;
	
	public class YourActivity extends AppCompatActivity {
	
	    @Override
	    protected void onCreate(Bundle savedInstanceState) {
	        super.onCreate(savedInstanceState);
	        setContentView(R.layout.activity_main);
	
	        // Get the Intent from the previous activity
	        Intent intent = getIntent();
	        Intent forward = intent.getParcelableExtra("key");
	        ComponentName name = forward.resolveActivity(getPackageManager());
	        if (name.getPackageName().equals("safe_package") && name.getClassName().equals("safe_class")) {
	            startActivity(forward);
	        }
	    }
	}
	```

