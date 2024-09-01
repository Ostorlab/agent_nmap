To disable debug mode in Phonegrap, follow the steps:

1. **Locate the Configuration File:** In your PhoneGap project, there should be a configuration file where you can specify various settings for your app. This file is usually named `config.xml`.

2. **Open the Configuration File:** Use a text editor to open the `config.xml` file.

3. **Find the Debug Mode Setting:** Look for a setting related to debug mode in the `config.xml` file. This setting might vary depending on the version of PhoneGap you are using, but it could be something like `<preference name="debug" value="true" />`.

4. **Change the Value:** Modify the value of the debug mode setting to `false`. So, if it's currently set to `true`, change it to `false`.

5. **Save the Changes:** Save the `config.xml` file after making the necessary modifications.

6. **Rebuild Your App:** If you've already built your app, you'll need to rebuild it after making the changes to the `config.xml` file.