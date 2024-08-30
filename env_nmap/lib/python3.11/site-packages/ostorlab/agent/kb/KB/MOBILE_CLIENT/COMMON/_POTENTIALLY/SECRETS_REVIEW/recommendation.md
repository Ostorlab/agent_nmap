Sensitive data should never be included with the application itself. Instead, secure methods for encrypting, storing, and retrieving credentials for your services should be used to access this data as needed.

To prevent the risk of overbilling, consider implementing API key pinning or using authenticated APIs for services with potentially high usage costs. API key pinning helps to restrict the use of a key to a specific application by requiring a cryptographic signature, and it can be enabled by the service provider (e.g., Google Maps).

For keys that may allow unauthorized access, it is important to restrict permissions and roles to non-critical functions, or to expose the service through an authenticated API.

To further enhance security, the API should also have proper access controls and rate-limiting in place, and keys should be rotated regularly to prevent unauthorized use.