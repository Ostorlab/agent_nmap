The recommended TLS configuration should enforce the following recommendations:

* Restrict to `TLSv1` and above, with `TLS1.2` being preferred
* If `SSLv3` is required, it is advised to implement the `TLS Fallback SCSV` feature to prevent protocol downgrade
  attacks
* Disable Anonymous Diffie-Hellman (`ADH`)
* Disable `aNULL` and `eNull` cipher suites
* Disable Export key exchange suites
* Remove `RC4` support
* Remove `DES` support
* Remove `MD5` support
* Prefere `SHA256` over `SHA1`
* Prefer `AES128` over `AES256` as 256 offers little security advantages and is less robust to timing attacks
* Disable Client-Initiated Renegotiation
* Disable TLS compression
* Offer only ciphers with a key length of greater than 128bit
* Offer cipher suites with Perfect-Forward Secrecy protocol properties (`DHE`, `ECDHE`)
* Use custom Diffie-Hellman group to protect against Logjam attack
* Implement the HTTP Strict Transport Security header field
* Implement `OSCP stapling`

Sample of a secure TLS configuration for Nginx generated
with [Mozilla SSL Configuration Generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/)

=== "Nginx"
	```nginx
	    server {
	        listen 443 ssl;
	    
	        # certs sent to the client in SERVER HELLO are concatenated in ssl_certificate
	        ssl_certificate /path/to/signed_cert_plus_intermediates;
	        ssl_certificate_key /path/to/private_key;
	        ssl_session_timeout 1d;
	        ssl_session_cache shared:SSL:50m;
	        ssl_session_tickets off;
	    
	        # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
	        ssl_dhparam /path/to/dhparam.pem;
	    
	        # modern configuration. tweak to your needs.
	        ssl_protocols TLSv1.1 TLSv1.2;
	        ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK';
	        ssl_prefer_server_ciphers on;
	    
	        # HSTS (ngx_http_headers_module is required) (15768000 seconds = 6 months)
	        add_header Strict-Transport-Security max-age=15768000;
	    
	        # OCSP Stapling ---
	        # fetch OCSP records from URL in ssl_certificate and cache them
	        ssl_stapling on;
	        ssl_stapling_verify on;
	    
	        ## verify chain of trust of OCSP response using Root CA and Intermediate certs
	        ssl_trusted_certificate /path/to/root_CA_cert_plus_intermediates;
	    
	        resolver <IP DNS resolver>;
	    
	        ....
	    }
	```

