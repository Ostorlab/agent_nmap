Access control is only effective if enforced in trusted server-side code or server-less API, where the attacker cannot
modify the access control check or metadata.

* Except for public resources, deny by default.
* Implement access control mechanisms once and re-use them throughout the application, including minimizing CORS
  usage.
* Model access controls should enforce record ownership rather than accepting that the user can create, read, update,
  or delete any record.
* Domain models should enforce unique application business limit requirements.
* Disable web server directory listing and ensure file metadata (e.g., .git) and backup files are not present within web
  roots.
* Log access control failures and alert admins when appropriate (e.g., repeated failures).
* Rate limit API and controller access to minimize the harm from automated attack tooling.
* JWT tokens should be invalidated on the server after logout. Developers and QA staff should include functional access
  control units and integration tests.
