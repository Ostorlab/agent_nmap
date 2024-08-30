Configure your webserver to redirect HTTP requests to HTTPS.

i.e. for Apache, you should have modification in the httpd.conf. For more configurations, please refer to External
References section.

=== "Bash"
	```shell
	# load module
	LoadModule headers_module modules/mod_headers.so
	
	# redirect all HTTP to HTTPS (optional)
	<VirtualHost *:80>
	       ServerAlias *
	       RewriteEngine On
	       RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [redirect=301]
	</VirtualHost>
	
	# HTTPS-Host-Configuration
	<VirtualHost *:443>
	      # Use HTTP Strict Transport Security to force client to use secure connections only
	      Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
	
	      # Further Configuration goes here
	      [...]
	</VirtualHost>
	```
