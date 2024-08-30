To prevent object serialization vulnerabilities, the application must either:

* Accept serialized objects from trusted sources only
* Use serialization primitive data types only

If these measures are not possible, consider the following:

* Implementing integrity checks such as digital signatures on any serialized objects to prevent hostile object creation
  or data tampering.
* Enforcing strict type constraints during deserialization before object creation as the code typically expects a
  definable set of classes. However, bypasses to this technique have been demonstrated, so reliance solely on this is
  not advisable.
* Isolating and running code that deserializes in low privilege environments when possible.
* Logging deserialization exceptions and failures, such as where the incoming type is not the expected type or the
  deserialization throws exceptions.
* Restricting or monitoring incoming and outgoing network connectivity from containers or servers that deserialize.
* Monitoring deserialization, alerting if a user deserializes constantly.
