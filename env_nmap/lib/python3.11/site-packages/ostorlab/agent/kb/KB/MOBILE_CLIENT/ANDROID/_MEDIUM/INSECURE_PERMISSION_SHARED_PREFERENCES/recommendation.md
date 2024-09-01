Shared Preferences are XML files to store private primitive data in key-value pairs. Data Types include Booleans, floats, ints, longs, and strings.

Shared preferences must never be set with the permission `MODE_WORLD_READABLE` or `MODE_WORLD_READABLE`, unless explicitly required for sharing information across apps.

Instead, shared permissions should have the mode `MODE_PRIVATE` (default mode), this mode means that only the application that created the shared preferences can access/modify them.

=== "Java"
	```java
      SharedPreferences sharedPreferences = getSharedPreferences("MyPreferences", Context.MODE_PRIVATE);
      SharedPreferences.Editor editor = sharedPreferences.edit();
      editor.putString("language", "en-US");
      editor.apply();
    ```