To mitigate risks associated with exporting receivers in Android applications, export only when essential. Additionally, ensure the exported BroadcastReceiver is protected with the necessary permissions to minimize potential security vulnerabilities.

=== "XML"
   ```xml
    <receiver android:name=".MyReceiver" android:exported="true" android:permission="your_permission">
        <intent-filter>
            <action android:name="android.intent.action.ACTION1" />
            <action android:name="android.intent.action.ACTION2" />
        </intent-filter>
    </receiver>
   ```
