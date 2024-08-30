Below are the recommended ATS settings:

- `NSAllowsArbitraryLoads`: Set to `NO` to enforce ATS restrictions, enhancing overall network security by limiting arbitrary network connections.
- `NSAllowsArbitraryLoadsForMedia`: Set to `NO` unless necessary for loading specifically encrypted media, ensuring that only secure connections are permitted for media content.
- `NSAllowsArbitraryLoadsInWebContent`: Set to `NO` unless required for specific functionality, as enabling it may compromise ATS protections within web views.
- `NSExceptionAllowsInsecureHTTPLoads`: Set to `NO` to enforce HTTPS connections and maintain secure communication standards, minimizing the risk of data interception.
- `NSExceptionMinimumTLSVersion`: Set to the latest TLS version supported by your app and server infrastructure, ensuring optimal security standards and protection against vulnerabilities associated with older TLS versions.