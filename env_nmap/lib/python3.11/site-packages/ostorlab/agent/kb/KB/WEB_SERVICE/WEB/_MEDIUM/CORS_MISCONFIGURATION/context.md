Cross-Origin Resource Sharing (CORS) misconfiguration is a notable vulnerability that can expose web applications to various security risks. Here's a contextual exploration of its risks, impacts, and real-world compromises:

### Real-world cases:
- **US Department of Defense**: An improper access control in CORS on a US Department of Defense Website allowed an attacker to steal user sessions (source)[https://hackerone.com/reports/470298].
- **Bitcoin Exchange**: A Bitcoin exchange had a vulnerability that could steal users’ private API key due to CORS misconfiguration, thereby risking the transfer of users' Bitcoin to an arbitrary address (source)[https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties].

### Business Impact:
The business impact of such vulnerabilities could be severe. The exploitation can lead to financial losses, especially in cases like the Bitcoin exchange. Moreover, it can cause reputational damage, legal issues, and loss of customer trust. Entities like the Department of Defense having such vulnerabilities exposed could also face national security implications. The remediation and legal costs post such incidents could be significant.

The mentioned examples illustrate the real dangers and substantial impacts associated with CORS misconfiguration, making it a critical area for web security attention and action.