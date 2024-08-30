Android Network Security Configuration is an XML file that enables a declarative setting of the application network security.

### Add Network security configuration to your application:

1- Create a new XML file in your app's res/xml directory. Name it `network_security_config.xml`, or any other suitable name.
2- Define Security Configurations, see examples below
3- Apply Configuration to the Manifest:

=== "XML"
	```xml
	<application
			android:networkSecurityConfig="@xml/network_security_config"
			<!-- Other attributes -->
			>
			<!-- Other configurations -->
	</application>	
	```


### Network security configuration examples

* Custom Certificate Authority with support for debug only settings

=== "XML"
	```xml
	<?xml version="1.0" encoding="utf-8"?>
	<network-security-config>
	    <debug-overrides>
	        <trust-anchors>
	            <certificates src="@raw/debug_cas"/>
	        </trust-anchors>
	    </debug-overrides>
	</network-security-config>
	```

* Declarative opt-out for clear-text traffic

=== "XML"
	```xml
	<?xml version="1.0" encoding="utf-8"?>
	<network-security-config>
	    <domain-config cleartextTrafficPermitted="false">
	        <domain includeSubdomains="true">secure.example.com</domain>
	    </domain-config>
	</network-security-config>
	```


* Declarative setting of certificate pinning keys

=== "XML"
	```xml
	<?xml version="1.0" encoding="utf-8"?>
	<network-security-config>
	    <domain-config>
	        <domain includeSubdomains="true">example.com</domain>
	        <pin-set expiration="2018-01-01">
	            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
	            <!-- backup pin -->
	            <pin digest="SHA-256">fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=</pin>
	        </pin-set>
	    </domain-config>
	</network-security-config>
	```
