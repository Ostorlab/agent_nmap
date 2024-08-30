To address the vulnerability, it is recommended to not use the custom scheme to redirect authentication tokens.

Developers should instead consider one of the following options:

- App to app integration like Google Identity Services and Facebook Express Login for Android
- [Android's verifiable AppLinks](https://developer.android.com/training/app-links/verify-android-applinks)  
- [iOS associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains)

### Kotlin

you need to have `/.well-known/assetlinks.json` hosted on your backend with a format like this:

```json
[
  {
    "relation": [
      "delegate_permission/common.handle_all_urls",
      "delegate_permission/common.get_login_creds"
    ],
    "target": {
      "namespace": "android_app",
      "package_name": "com.myapplication.android",
      "sha256_cert_fingerprints": [
        "APPLICATION_CERT_FINGERPRINT"
      ]
    }
  }
]
```

=== "AndroidManifest.xml"
	```xml
		<intent-filter android:autoVerify="true">
		<action android:name="android.intent.action.VIEW" />
		<category android:name="android.intent.category.DEFAULT" />
		<category android:name="android.intent.category.BROWSABLE" />
	
		<!-- If a user clicks on a shared link that uses the "http" scheme, your
			 app should be able to delegate that traffic to "https". -->
		<data android:scheme="http" />
		<data android:scheme="https" />
	
		<!-- Include one or more domains that should be verified. -->
		<data android:host="auth.myapp.com" />
	</intent-filter>
	```

=== "Kotlin"
	```kotlin
	Log.i(TAG, "Creating auth request for login hint: $loginHint")
	val authRequestBuilder: AuthorizationRequest.Builder = Builder(
		mAuthStateManager.getCurrent().getAuthorizationServiceConfiguration(),
		mClientId.get(),
		ResponseTypeValues.CODE,
		"https://auth.myapp.com/oauth/handler" // The redirect URI with an https scheme
	)
		.setScope(mConfiguration.getScope())
	if (!TextUtils.isEmpty(loginHint)) {
		authRequestBuilder.setLoginHint(loginHint)
	}
	mAuthRequest.set(authRequestBuilder.build())
	```

### iOS

For iOS, you need to have `/.well-known/apple-app-site-association` hosted on your backend with format like this:

```json
{
    "applinks": {
        "details": [{
            "appID": "ABCDE12345.com.myapplication.ios",
            "paths": ["/oauth/redirect/*"]
        }]
    },
    "appclips":{
        "apps":[
            "ABCDE12345.com.myapplication.ios"
        ]
    },
    "webcredentials":{
        "apps":[
            "ABCDE12345.com.myapplication.ios"
        ]
    }
}
```

=== "release.entitlements"
	```xml
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
		...
		<key>com.apple.developer.associated-domains</key>
		<array>
			<string>applinks:auth.myapp.com</string>
		</array>
		...
	</dict>
	</plist>
	```

=== "Swift"
	```swift
	func doAuthWithAutoCodeExchange(configuration: OIDServiceConfiguration, clientID: String, clientSecret: String?) {

        guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
            self.logMessage("Error accessing AppDelegate")
            return
        }

        // builds authentication request
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientID,
                                              clientSecret: clientSecret,
                                              scopes: [OIDScopeOpenID, OIDScopeProfile],
                                              redirectURL: "https://auth.myapp.com/oauth/handler",
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: nil)

        // performs authentication request
        logMessage("Initiating authorization request with scope: \(request.scope ?? "DEFAULT_SCOPE")")

        appDelegate.currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: self) { authState, error in

            if let authState = authState {
                self.setAuthState(authState)
                self.logMessage("Got authorization tokens. Access token: \(authState.lastTokenResponse?.accessToken ?? "DEFAULT_TOKEN")")
            } else {
                self.logMessage("Authorization error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
                self.setAuthState(nil)
            }
        }
    }
	```

### Multiplatform

=== "Gradle"
	```groovy
	// android/build.gradle

	android {
		// ...
		defaultConfig {
			// ...
			// Add the following line
			manifestPlaceholders = [auth0Domain: "auth.myapp.com", auth0Scheme: "https"]
		}
		// ...
	}
	```

=== "Dart"
	```dart
		final authorizationEndpoint =
			Uri.parse('http://example.com/oauth2/authorization');
		final tokenEndpoint = Uri.parse('http://example.com/oauth2/token');
		
		final identifier = 'my client identifier';
		final secret = 'my client secret';

		// Redirect URI with custom scheme
		final redirectUrl = Uri.parse('https://auth.myapp.com/oauth/handler');

		final credentialsFile = File('~/.myapp/credentials.json');

		Future<oauth2.Client> createClient() async {
		  var exists = await credentialsFile.exists();

		  if (exists) {
			var credentials =
				oauth2.Credentials.fromJson(await credentialsFile.readAsString());
			return oauth2.Client(credentials, identifier: identifier, secret: secret);
		  }
		
		  var grant = oauth2.AuthorizationCodeGrant(
			  identifier, authorizationEndpoint, tokenEndpoint,
			  secret: secret);
		
		  var authorizationUrl = grant.getAuthorizationUrl(redirectUrl);

		  await redirect(authorizationUrl);
		  var responseUrl = await listen(redirectUrl);
		
		  return await grant.handleAuthorizationResponse(responseUrl.queryParameters);
		}
	```