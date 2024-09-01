App Transport Security (ATS) enforces best practices in the secure connections between an app and its back end. ATS
prevents accidental disclosure, provides secure default behavior, and is easy to adopt; it is also on by default in iOS
9 and OS X v10.11. Therefore, you should adopt ATS as soon as possible, regardless of whether you're creating a new app
or updating an existing one.

* `NSAllowsArbitraryLoads`: If set to YES, disables all ATS restrictions for all network connections, apart from the
  connections to domains you configure individually in the optional NSExceptionDomains dictionary. The default value is
  NO.
* `NSAllowsArbitraryLoadsForMedia`: If set to YES, disables all ATS restrictions for media your app loads using the AV
  Foundation framework. Employ this key only for loading already encrypted media, such as files protected by FairPlay or
  by secure HLS, that do not contain personalized information. The default value is NO.
* `NSAllowsArbitraryLoadsInWebContent`: If set to YES, disables all ATS restrictions for requests made from web views.
  This lets your app use an embedded browser that can display arbitrary content without disabling ATS for the rest of
  your app. The default value is NO.
* `NSExceptionAllowsInsecureHTTPLoads`: If set to YES, it allows insecure HTTP loads for the named domain but does not
  change Transport Layer Security (TLS) requirements and does not affect HTTPS loads for the named domain. The default
  value is NO.
* `NSExceptionMinimumTLSVersion`: Specifies the minimum TLS version for network connections for the named domain,
  allowing connection using an older, less secure version of Transport Layer Security.
