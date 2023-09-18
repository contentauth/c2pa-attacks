## Samples

This directory contains the various sample files that you need to build your first malicious assertion.

These include:

* `C.jpg`: A base C2PA image with an existing manifest.
* `image.jpg`: A base image without any C2PA content credentials
* `test.json`: A valid manifest to embed into the image
* `es256_certs.pem` and `es256_private.key`: A certificate and key that can be used to sign the images.
* `author_name_regex.json`: An example JSON file with the C2PA_ATTACK keyword in the author's name field. This can be used with a regex command line: `-t regex`. This is not the only way to inject into the author's name field. You could also do this by using test.json along with `-t author` in the command line. This file is just to demonstrate a regex-based approach on a common field. The value C2PA_ATTACK could be put into any of the JSON value field that needs testing.
