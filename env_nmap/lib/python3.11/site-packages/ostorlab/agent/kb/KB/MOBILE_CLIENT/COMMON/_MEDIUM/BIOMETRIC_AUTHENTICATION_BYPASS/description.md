A secure implementation of mobile biometric authentication guarantees the need to use Face ID or Touch ID authentication to access the application’s sensitive data.  Such secure implementation goes beyond just verifying the fingerprint or the face to log in. It also includes encrypting the application's sensitive data using the biometric data.

This encryption adds an extra layer of protection, making it highly challenging for unauthorized individuals to access or use sensitive information. Encryption with biometric data becomes crucial in case an unauthorized party gains access to the device, via Malware or physical access.

### Android 

Android provides mechanisms to enforce biometric authentication to protect sensitive information. Biometric authentication has evolved over time to provide improved user experience, developer experience and improved security.

Previous implementation using `FingerprintManager` is deprecated and must not be used. Proper implementation must use`BiometricManager` with `BiometricPrompt` and `CryptoObject`.

`CryptoObject` provides cryptographic primitives for encryption, decryption and signature validation.

In the example below, calling the `authenticate` method without `cryptoObject` is vulnerable to authentication bypass:

=== "Kotlin"
	```kotlin
	fun showBiometricPrompt(
	    title: String = "Biometric Authentication",
	    subtitle: String = "Enter biometric credentials to proceed.",
	    description: String = "Input your Fingerprint or FaceID to ensure it's you!",
	    activity: AppCompatActivity,
	    listener: BiometricAuthListener,
	    cryptoObject: BiometricPrompt.CryptoObject? = null,
	    allowDeviceCredential: Boolean = false
	) {
	  // 1
	  val promptInfo = setBiometricPromptInfo(
	      title,
	      subtitle,
	      description,
	      allowDeviceCredential
	  )
	
	  // 2
	  val biometricPrompt = initBiometricPrompt(activity, listener)
	
	  // 3
	  biometricPrompt.apply {
	    if (cryptoObject == null) authenticate(promptInfo)
	    else authenticate(promptInfo, cryptoObject)
	  }
	}
	```

### iOS

The Local Authentication framework enables developers to request Touch ID authentication from users. To initiate this process, developers can invoke an authentication prompt using the evaluatePolicy function within the LAContext class. However, it's important to note that this approach is insecure: the function returns a boolean value, rather than providing a cryptographic object that can be utilized for decrypting sensitive data stored within the Keychain.

Without a cryptographic object, an attacker can manipulate the memory to bypass the biometric check and log in successfully to the application. However, they would be unable to interpret or utilize the application data if the encryption is used with the biometric data. This helps to maintain the confidentiality of the application's sensitive information, thereby safeguarding the privacy and security of users' data.

In the example below from DVIA, it is possible to bypass biometric authentication by hooking evaluatePolicy using frida:

=== "Swift"
	```Swift
	+(void)authenticateWithTouchID {

    LAContext *myContext = [[LAContext alloc] init];
    NSError *authError = nil;
    NSString *myLocalizedReasonString = @"Please authenticate yourself";

    if ([myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
        [myContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                  localizedReason:myLocalizedReasonString
                            reply:^(BOOL success, NSError *error) {
                                if (success) {
                                    dispatch_async(dispatch_get_main_queue(), ^{
                                    [TouchIDAuthentication showAlert:@"Authentication Successful" withTitle:@"Success"];
                                    });
                                } else {
                                    dispatch_async(dispatch_get_main_queue(), ^{
                                       [TouchIDAuthentication showAlert:@"Authentication Failed !" withTitle:@"Error"];
                                    });
                                }
                            }];
		} else {
			dispatch_async(dispatch_get_main_queue(), ^{
				[TouchIDAuthentication showAlert:@"Your device doesn't support Touch ID or you haven't configured Touch ID authentication on your device" withTitle:@"Error"];
			});
		}
	}
	```