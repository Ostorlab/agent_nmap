To avoid leaking credentials in application logs, consider the following:

* Ensure that your logging framework or system does not include sensitive information like passwords or API keys in logs. Review your code for any sensitive data being logged.
* Set logging levels to debug to avoid having sensitive information logged in production app. 
* Remove debug log files before deploying the application into production.
* Adjust configurations appropriately when software is transitioned from a debug state to production.
* Remove any test credentials or hardcoded credentials before deploying the application.