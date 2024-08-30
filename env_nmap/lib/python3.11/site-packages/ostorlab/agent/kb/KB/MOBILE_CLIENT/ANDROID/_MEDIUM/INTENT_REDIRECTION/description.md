An Android Intent redirection vulnerability occurs when an app sends an Intent (a messaging object used to request an action from another app component) to another component, but an attacker manipulates the Intent to redirect it to a malicious app or activity. This can lead to unauthorized access to app components.

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
	
	        if (forward != null) {
	            startActivity(forward);
	        }
	    }
	}
	```

