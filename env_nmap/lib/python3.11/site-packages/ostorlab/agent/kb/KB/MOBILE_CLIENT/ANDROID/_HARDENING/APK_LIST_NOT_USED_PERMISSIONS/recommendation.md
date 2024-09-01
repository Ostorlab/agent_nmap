Remove unused declared permissions from the application's manifest

If the application for example declares the permission `ACCESS_FINE_LOCATION` but does not use it, you can remove it from your application manifest:

- Before:

=== "XML"
  ```xml
  <manifest xmlns:android="http://schemas.android.com/apk/res/android"
      package="com.example.myapp">
  
      <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
  
      <application
          android:allowBackup="true"
          android:icon="@mipmap/ic_launcher"
          android:label="@string/app_name"
          android:roundIcon="@mipmap/ic_launcher_round"
          android:supportsRtl="true"
          android:theme="@style/AppTheme">
          <!-- Other application components -->
      </application>
  
  </manifest>
  ```

- After:

=== "XML"
  ```xml
  <manifest xmlns:android="http://schemas.android.com/apk/res/android"
      package="com.example.myapp">
  
      <application
          android:allowBackup="true"
          android:icon="@mipmap/ic_launcher"
          android:label="@string/app_name"
          android:roundIcon="@mipmap/ic_launcher_round"
          android:supportsRtl="true"
          android:theme="@style/AppTheme">
          <!-- Other application components -->
      </application>
  
  </manifest>
  ```