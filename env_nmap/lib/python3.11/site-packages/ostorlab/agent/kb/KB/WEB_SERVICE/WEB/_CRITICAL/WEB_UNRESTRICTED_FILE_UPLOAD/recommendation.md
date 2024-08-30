To mitigate the risks associated with unrestricted files upload, consider the following:

- **Validate File Type:** Implement server-side validation to ensure that only authorized file types are allowed to be uploaded. Whitelist allowed file extensions and reject any files with disallowed extensions. Avoid using client-side validation alone, as it can be bypassed.
- **Check File Content:** Verify the content of the uploaded files to ensure they match their file type. For example, for image uploads, use libraries or tools to check the file headers to confirm they are indeed images.
- **Rename Uploaded Files:** Rename uploaded files to prevent attackers from executing them by guessing the filename. Use a combination of random strings and server-generated unique identifiers to create new filenames for uploaded files.
- **Store Uploaded Files in a Secure Location:** Store uploaded files outside of the web root directory to prevent direct access through URLs. You can use S3 buckets for example.
- **Scan Uploaded Files for Malware:** Utilize antivirus or anti-malware scanners to scan uploaded files for malicious content. Implement regular scans to ensure that no malicious files are present on the server.
- **Monitor File Upload Activities:** Implement logging and monitoring mechanisms to track file upload activities. Monitor for any suspicious or unusual file upload patterns and take immediate action upon detection.


=== "Express"
  ```javascript
  const express = require('express');
  const multer = require('multer');
  const path = require('path');
  const { v4: uuidv4 } = require('uuid');
  
  const app = express();
  
  // Define storage for uploaded files
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
      const ext = path.extname(file.originalname);
      cb(null, uuidv4() + ext);
    }
  });
  
  // File filter to allow only specified file extensions
  const fileFilter = (req, file, cb) => {
    const allowedExtensions = ['.jpg', '.jpeg', '.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExtensions.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed!'), false);
    }
  };
  
  // Initialize multer with storage and file filter
  const upload = multer({ storage: storage, fileFilter: fileFilter });
  
  // POST endpoint for file upload
  app.post('/upload', upload.single('file'), (req, res) => {
    res.send('File uploaded successfully!');
  });
  
  app.listen(3000, () => {
    console.log('Server is running on port 3000');
  });
  ```


=== "Django"
  ```python
  from django.conf import settings
  from django.core.files.storage import FileSystemStorage
  from django.http import HttpResponseBadRequest
  from django.views.decorators.csrf import csrf_exempt
  from django.views.decorators.http import require_POST
  import os
  from uuid import uuid4
  
  @require_POST
  def upload_file(request):
      if request.method == 'POST' and request.FILES['file']:
          file = request.FILES['file']
          allowed_extensions = ['.jpg', '.jpeg', '.png']
          ext = os.path.splitext(file.name)[1]
          if ext.lower() not in allowed_extensions:
              return HttpResponseBadRequest('File type not allowed!')
          fs = FileSystemStorage()
          filename = fs.save(str(uuid4()) + ext, file)
          return HttpResponse('File uploaded successfully!')
      else:
          return HttpResponseBadRequest('No file found!')
  ```

=== "PHP"
  ```php
  <?php
  $uploadDir = 'uploads/';
  
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
      $file = $_FILES['file'];
      $allowedExtensions = array('.jpg', '.jpeg', '.png');
      $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
      if (!in_array($ext, $allowedExtensions)) {
          http_response_code(400);
          echo 'File type not allowed!';
          exit;
      }
  
      $uploadFile = $uploadDir . uniqid() . '.' . $ext;
      if (move_uploaded_file($file['tmp_name'], $uploadFile)) {
          echo 'File uploaded successfully!';
      } else {
          http_response_code(500);
          echo 'Error uploading file.';
      }
  } else {
      http_response_code(400);
      echo 'No file found!';
  }
  ?>
  ```