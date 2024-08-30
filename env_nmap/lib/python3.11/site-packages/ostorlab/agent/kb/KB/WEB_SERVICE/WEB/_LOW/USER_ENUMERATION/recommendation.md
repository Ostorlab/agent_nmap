Making sure no pages or APIs can be used to differentiate between a
valid and invalid username

- Login:

  Make sure to return a generic "No such username or password" message
  when a login fails. In addition, make sure the HTTP response and the
  time taken to respond are no different when a username does not
  exist and an incorrect password is entered.

- Password Reset:

  Make sure your "forgotten password" page does not reveal usernames.
  If your password reset process involves sending an email, have the
  user enter their email address. Then send an email with a password
  reset link if the account exists.

- Registration:

  Avoid having your site tell people that a supplied username is
  already taken. If your usernames are email addresses, send a
  password reset email if a user tries to sign-up with a current
  address. If usernames are not email addresses, protect your sign-up
  page with a CAPTCHA.

- Profile Pages:

  If your users have profile pages, make sure they are only visible to
  other users who are already logged in. If you hide a profile page,
  ensure a hidden profile is indistinguishable from a non-existent
  profile.
