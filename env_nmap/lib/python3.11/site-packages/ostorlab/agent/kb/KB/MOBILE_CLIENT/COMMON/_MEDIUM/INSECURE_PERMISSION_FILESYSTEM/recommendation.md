* File Must Be Created as a Private File in Principle: Regardless of the contents of the
  information to be stored, files should be set private, in principle. From Android security designing point
  of view, exchanging information and its access control should be done in Android system like Content
  Provider and Service, etc., and in case there’s a reason that is impossible, it should be considered to be
  substituted by file access permission as alternative method.

* Must Not Create Files that Be Allowed to Read/Write Access from Other Applications: When permitting other applications
  to
  read/write files, information stored in files cannot be controlled. So, sharing information by using
  read/write public files should not be considered from both security and function/designing points of
  view.

* Using Files Stored in External Device (e.g. SD Card) Should Be Requisite Minimum: Storing files in external
  memory device like SD card, leads to holding the potential problems from security and functional points
  of view
    * Sensitive information should not be saved in a file of external memory device, in principle
    * In case sensitive information is saved in a file of external memory device, it should be encrypted.
    * In case saving in a file of external memory device information that will be trouble if it’s tampered
      by other application or users, it should be saved with electrical signature.
    * When reading in files in external memory device, use data after verifying the safety of data to read
      in.
    * Application should be designed supposing that files in external memory device can be always
      deleted.

* Use of world access permissions should be used only when strictly required. Other means of sharing data between
  applications are recommended instead of sharing file using insecure permissions.

* Application Should Be Designed Considering the Scope of File