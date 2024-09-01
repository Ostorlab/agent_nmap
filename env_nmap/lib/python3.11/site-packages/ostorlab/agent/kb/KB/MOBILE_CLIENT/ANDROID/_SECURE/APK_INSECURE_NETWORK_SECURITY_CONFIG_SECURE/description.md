Android Network Security Configuration enables a declarative setting of the application network security.

The features enable configuring:

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



* Declarative opt-out for cleartext traffic

=== "XML"
	```xml
	<?xml version="1.0" encoding="utf-8"?>
	<network-security-config>
	    <domain-config cleartextTrafficPermitted="false">
	        <domain includeSubdomains="true">secure.example.com</domain>
	    </domain-config>
	</network-security-config>
	```



* Declartive setting of certificate pinning keys

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

