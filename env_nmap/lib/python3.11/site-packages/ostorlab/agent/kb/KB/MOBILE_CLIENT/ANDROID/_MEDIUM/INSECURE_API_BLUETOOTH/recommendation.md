It is recommended that you use secure means of connection and information exchange with Bluetooth, which is possible with the `createRfcommSocketToServiceRecord`, `listenUsingRfcommWithServiceRecord` that allow the socket connection to be encrypted to mitigate the risk of MiTM attacks.

=== "Client"
  ```java
  import java.io.IOException;
  import java.util.UUID;
  import javax.bluetooth.*;
  import javax.microedition.io.Connector;
  import javax.microedition.io.StreamConnection;
  
  public class BluetoothClient {
  
      private static final String SERVER_MAC_ADDRESS = "00:11:22:33:44:55"; // Replace with your server's MAC address
      private static final UUID SERIAL_UUID = new UUID(0x1101);
  
      public static void main(String[] args) {
          try {
              // Discovering and connecting to the server device
              LocalDevice localDevice = LocalDevice.getLocalDevice();
              DiscoveryAgent discoveryAgent = localDevice.getDiscoveryAgent();
              RemoteDevice remoteDevice = discoveryAgent.getRemoteDevice(SERVER_MAC_ADDRESS);
              String url = "btspp://" + SERVER_MAC_ADDRESS + ":" + SERIAL_UUID + ";authenticate=false;encrypt=false;master=false";
              StreamConnection streamConnection = (StreamConnection) Connector.open(url);
  
              // Connected successfully, you can now read and write data through the streamConnection
  
              // Close the connection when done
              streamConnection.close();
          } catch (IOException e) {
              e.printStackTrace();
          } catch (BluetoothStateException e) {
              e.printStackTrace();
          }
      }
  }
  ```

=== "Server"
  ```java
  import java.io.IOException;
  import java.io.InputStream;
  import java.io.OutputStream;
  import javax.bluetooth.*;
  import javax.microedition.io.Connector;
  import javax.microedition.io.StreamConnection;
  import javax.microedition.io.StreamConnectionNotifier;
  
  public class BluetoothServer {
  
      private static final UUID SERIAL_UUID = new UUID(0x1101);
      private static final String SERVER_NAME = "BluetoothServer";
  
      public static void main(String[] args) {
          try {
              // Create a Bluetooth server
              LocalDevice localDevice = LocalDevice.getLocalDevice();
              localDevice.setDiscoverable(DiscoveryAgent.GIAC);
  
              // Create a server connection and start listening
              String url = "btspp://localhost:" + SERIAL_UUID + ";name=" + SERVER_NAME;
              StreamConnectionNotifier connectionNotifier = (StreamConnectionNotifier) Connector.open(url);
  
              System.out.println("Server started. Waiting for clients to connect...");
  
              // Listen for incoming connections
              while (true) {
                  StreamConnection connection = connectionNotifier.acceptAndOpen();
  
                  // Handle the client connection in a separate thread
                  Thread clientThread = new Thread(new ClientHandler(connection));
                  clientThread.start();
              }
          } catch (IOException e) {
              e.printStackTrace();
          } catch (BluetoothStateException e) {
              e.printStackTrace();
          }
      }
  
      // Runnable class to handle client connections
      static class ClientHandler implements Runnable {
          private StreamConnection connection;
  
          public ClientHandler(StreamConnection connection) {
              this.connection = connection;
          }
  
          @Override
          public void run() {
              try {
                  System.out.println("Client connected: " + connection);
  
                  // Get the input and output streams for communication
                  InputStream inputStream = connection.openInputStream();
                  OutputStream outputStream = connection.openOutputStream();
  
                  // Perform communication with the client, for example, read and write data
  
                  // Close the connection when done
                  inputStream.close();
                  outputStream.close();
                  connection.close();
  
                  System.out.println("Client disconnected: " + connection);
              } catch (IOException e) {
                  e.printStackTrace();
              }
          }
      }
  }
  ```