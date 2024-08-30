To mitigate risk of URL scheme hijacking on iOS, it is recommended to use
iOS universal links.

Universal links prevent malicious application interception through a vetting
process using standard web links (HTTP/HTTPS).

For instance, the Telegram app supports both custom URL schemes and universal links:

* `tg://resolve?domain=fridadotre` is a custom URL scheme and uses the `tg://` scheme.
* `https://telegram.me/fridadotre` is a universal link and uses the `https://` scheme.

This model ensures universal links are unique, and secure without sacrificing simplicity
and flexibility.
