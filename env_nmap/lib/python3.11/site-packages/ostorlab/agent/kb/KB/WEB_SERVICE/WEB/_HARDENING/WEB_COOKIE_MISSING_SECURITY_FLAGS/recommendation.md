Add missing security attributes to the cookies. Adding the flag depends
on the framework used and can either be a global setting or be done
manually by adding the flags to the request.

For session cookies managed by PHP, the flag is set either in `php.ini`:

```http request
session.cookie_secure = True
```

Or in code:

=== "PHP"
	```php
	setcookie ( string $name [, string $value = "" [, int $expires = 0 [, string $path = "" [, string $domain = "" [, bool $secure = FALSE [, bool $httponly = FALSE ]]]]]] ) : bool
	setcookie ( string $name [, string $value = "" [, array $options = [] ]] ) : bool
	```

For accurate details on how to add the flag, check the documentation of
your framework.
