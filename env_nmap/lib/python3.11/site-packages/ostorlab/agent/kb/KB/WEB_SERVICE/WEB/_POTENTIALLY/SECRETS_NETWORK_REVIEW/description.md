The application is detected to transmit secret credentials, like SSH keys, private certificates, or private API keys
over
the network.

Secrets can be split into two categories with different risk profiles:

* Over-billing: affects API keys that grant access to services like Google Maps and are billed by a number of requests.
  Attackers will harvest the keys to access the service without paying while the target is paying for the service.

* Unauthorized Access: affects keys, secrets, and tokens that grant access to services like S3 buckets. If
  the service is improperly configured, attackers can get access to unauthorized data or elevate their privileges
  through other services.
