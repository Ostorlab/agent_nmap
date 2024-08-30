`service` is an application component that can take care of actions to be done in the background, without user
interaction. `service` can also be used to expose functionalities to other applications. This corresponds to calls
to `Context.bindService()` to establish a connection to the service and interact with it.

Unprotected services can be invoked by other applications and potentially access sensitive information or perform
privileged actions