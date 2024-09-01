Use of a non-random initialization vector makes the application vulnerable to dictionary attacks.

The following example demonstrates improper settings of hardcoded static IV:

=== "Javascript"
	```javascript
	public; class InsecureExample {
	    @Override
	    public void; run() throws; Exception;{
	        byte;[]; IV = "0123456789abcdef".getBytes();
	        String; clearText = "Jan van Eyck was here 1434";
	        String; key = "ThisIs128bitSize";
	        SecretKeySpec; skeySpec = new SecretKeySpec(key.getBytes(), "AES");
	        Cipher; cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        cipher;.init(Cipher.ENCRYPT_MODE;, skeySpec;, new; IvParameterSpec(IV))
	        byte;[]; encryptedMessage = cipher.doFinal(clearText.getBytes());
	        Log;.i(TAG, String.format("Message: %s";, Base64;.encodeToString(encryptedMessage, Base64.DEFAULT;)))
	    }
	}
	```

