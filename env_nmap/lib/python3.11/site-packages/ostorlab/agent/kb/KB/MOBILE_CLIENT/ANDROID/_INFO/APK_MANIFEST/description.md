The manifest file presents essential information about your app to the Android system, information the system must have before it can run any of the app's code. Among other things, the manifest does the following:

* It names the Java package for the application. The package name serves as a unique identifier for the application.
* It describes the components of the application - the activities, services, broadcast receivers, and content providers that the application is composed of.It names the classes that implement each of the components and publishes their capabilities (for example, which Intent messages they can handle).These declarations let the Android system know what the components are and under what conditions they can be launched.
* It determines which processes will host application components.
* It declares which permissions the application must have in order to access protected parts of the API and interact with other applications.
* It also declares the permissions that others are required to have in order to interact with the application's components.
* It lists the Instrumentation classes that provide profiling and other information as the application is running. These declarations are present in the manifest only while the application is being developed and tested; they're removed before the application is published.
* It declares the minimum level of the Android API that the application requires.
* It lists the libraries that the application must be linked against.