Firebase Realtime Database Rules determine who has read and written access to your database, how your data is
structured, and what indexes exist.

Insecure Database permissions are a common issue, leading to unauthorized access to your database. Firebase
provides tools to enforce Authentication, Authorization, and even Data Validation.

The following are common misconfiguration issues to avoid:

Read and write access to all users:

```json
{
  "rules": {
    ".read": true,
    ".write": true
  }
}
```

Any logged-in user has read and write access to your entire database:

```json
{
  "rules": {
      ".read": "auth !== null",
      ".write": "auth !== null"
   }
}
```

Realtime Database Rules cascade, with rules at more shallow, parent paths overriding rules at deeper child nodes.
Remember to write a rule at a child node that it can only grant additional privileges. You can't refine or
revoke access to data at a deeper path in your database.

```json
{
  "rules": {
     "foo": {
        // allows read to /foo/*
        ".read": "data.child('baz').val() === true",
        "bar": {
          /* ignored, since read was allowed already */
          ".read": false
        }
     }
  }
}
```
