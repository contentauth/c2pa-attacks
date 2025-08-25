## Samples

This directory contains the various sample files that you need to build your first malicious assertion.

These include:

* `C.jpg`: A base C2PA image with an existing manifest.
* `image.jpg`: A base image without any C2PA content credentials
* `test.json`: A valid C2PA version 1 claim manifest to embed into the image
* `test_claim_v2.json`: A valid C2PA version 2 claim manifest to embed into the image
* `author_name_regex.json`: An example C2PA version 1 claim manifest file with the C2PA_ATTACK keyword in the author's name field and the id field. For unit testing, you would most likely want to only use field at a time. The use of two fields is just to demonstrate that it will replace all occurrences of the string with each pass. This file can be used with the regex command line: `-t regex`. This is not the only way to inject into the author's name field. You could also do this by using test.json along with `-t author` in the command line. This file is just to demonstrate a regex-based approach on a common field. The value C2PA_ATTACK can be put into any JSON value field that needs testing.
* `title_regex_v2_example.json`: An example C2PA version 2 claim manifest with the C2PA_ATTACK keyword in the title field. This file can be used with the regex command line: `-t regex`. The value C2PA_ATTACK can be put into any JSON value field that needs testing.
* `es256_certs.pem` and `es256_private.key`: A certificate and key that can be used to sign the images.
* `ps256.pem` and `ps256.pub`: A certificate and key for testing with ps256 signature algorithms.
* `malicious_certificate.pem` and `malicious_certificate.key`: A certificate and key that can be used to sign the images. This certificate contains malicious characters in the Subject field to help test for injections when displaying the certificate chain.
* `malicious_certificate.pem.expired`: This certificate is expired and could be used to test expiration checks.
* `malicious_root.pem` and `malicious_intermediate.pem`: The intermediate and root certificate authorities for the malicious certificate chain. These are useful if you need to do validation of the malicious_certificate.pem chain during testing.
* `malicious_certificate.json`: An example valid version 1 test file that can be used with the malicious certificate signing key.
* `trust_anchors.pem`:  A list of trust anchors (in PEM format) used to validate the manifest certificate chain. To be valid, the manifest certificate chain must lead to a certificate on the trust list. All certificates in the trust anchor list must have the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) and the CA attribute of this extension must be `True`.
* `store.cfg`: The trust store config with the allowed set of custom certificate extended key usages (EKUs). Each entry in the list is an object identifiers in [OID dot notation](http://www.oid-info.com/#oid) format.
* `allowed_list.pem`: A list of end-entity certificates (in PEM format) to trust. These certificates are used to sign the manifest. Supersedes the `trust_anchors` setting. The list must NOT contain certificates with the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) with the CA attribute `True`.