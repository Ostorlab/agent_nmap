Depending on your needs, consider one of the configurations for the `Referrer Policy` header:

- **No Referrer (no-referrer):** This policy completely hides the referring URL when navigating to another page. This is the most privacy-preserving option, but it might break some functionality that relies on the referrer, such as analytics or login systems.

- **Origin Only (origin):** This policy sends only the origin (protocol + domain + port) of the referring page as the referrer, excluding the path and query parameters. This strikes a balance between privacy and functionality.

- **Same Origin (same-origin):** This policy sends the full URL as the referrer when navigating within the same origin, but only sends the origin when navigating to a different origin. This maintains privacy while allowing referrer information within the same site.

- **Strict Origin When Cross-Origin (strict-origin-when-cross-origin):** This policy sends the full URL as the referrer when navigating to the same origin, but only sends the origin when navigating to a different origin via a non-secure connection (HTTP to HTTPS). It sends no referrer information when navigating from a secure origin to a non-secure origin.

- **Unsafe URL (unsafe-url):** This policy sends the full URL including path and query parameters as the referrer, regardless of whether the destination is within the same origin or not. This is the least privacy-preserving option.





