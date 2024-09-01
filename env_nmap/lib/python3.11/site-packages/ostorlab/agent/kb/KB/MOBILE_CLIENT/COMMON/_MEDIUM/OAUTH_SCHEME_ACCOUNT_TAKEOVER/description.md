The vulnerability arises from the application's use of a custom scheme in the `redirect_uri` parameter during OAuth authentication. 

In a typical OAuth scenario, `redirect_uri` should be guaranteed to belong to the client application (identified by `client_id`) that requests data from an identity provider (Google, Facebook, Github...). Using a custom scheme breaks that premise as it can be claimed by the application on the user's device.

An example attack scenario is when a malicious app claims the custom scheme used by some OAuth client application and triggers an OAuth authentication flow to the target app, once the user successfully performs login and consents they'll be redirected to the malicious app with the authentication token generated from the OAuth flow, allowing the malicious app to take over their account. 

Attackers can **bypass user interaction** by leveraging certain techniques like express authentication flow or use OAuth parameters that are meant to skip the consent prompt if the user gave their consent before.

### Kotlin

=== "AndroidManifest.xml"
	```xml
	<activity android:exported="true" android:name="net.openid.appauth.RedirectUriReceiverActivity">
		<intent-filter>
			<action android:name="android.intent.action.VIEW"/>
			<category android:name="android.intent.category.DEFAULT"/>
			<category android:name="android.intent.category.BROWSABLE"/>
			<data android:host="oauthredirect" android:scheme="mycustomscheme"/>
		</intent-filter>
	</activity>
	```

=== "Kotlin"
	```kotlin
	Log.i(TAG, "Creating auth request for login hint: $loginHint")
	val authRequestBuilder: AuthorizationRequest.Builder = Builder(
		mAuthStateManager.getCurrent().getAuthorizationServiceConfiguration(),
		mClientId.get(),
		ResponseTypeValues.CODE,
		"mycustomscheme://oauthredirect" // Redirect URI with custom scheme
	)
		.setScope(mConfiguration.getScope())
	if (!TextUtils.isEmpty(loginHint)) {
		authRequestBuilder.setLoginHint(loginHint)
	}
	mAuthRequest.set(authRequestBuilder.build())
	```

### iOS

=== "Info.plist"
	```xml
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
	  ...
	  <key>CFBundleURLTypes</key>
	  <array>
		<dict>
			<key>CFBundleTypeRole</key>
			<string>Editor</string>
			<key>CFBundleURLSchemes</key>
			<array>
			  <string>mycustomscheme</string>
			</array>
		  </dict>
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
                                              redirectURL: "mycustomscheme://oauthredirect",
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
			manifestPlaceholders = [auth0Domain: "oauthredirect", auth0Scheme: "mycustomscheme"]
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
		final redirectUrl = Uri.parse('mycustomscheme://oauthredirect');

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