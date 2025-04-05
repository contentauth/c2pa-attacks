## Samples

This directory contains the various sample files that you need to build your first malicious assertion.

These include:

* `C.jpg`: A base C2PA image with an existing manifest.
* `image.jpg`: A base image without any C2PA content credentials
* `test.json`: A valid manifest to embed into the image
* `es256_certs.pem` and `es256_private.key`: A certificate and key that can be used to sign the images.
* `psa256.pem` and `psa256.pub`: A certificate and key for testing with ps256 signature algorithms.
* `malicious_certificate.pem` and `malicious_certificate.key`: A certificate and key that can be used to sign the images. This certificate contains malicious characters in the Subject field to help test for injections when displaying the certificate chain.
* `malicious_certificate.pem.expired`: This certificate is expired and could be used to test expiration checks.
* `malicious_root.pem` and `malicious_intermediate.pem`: The intermediate and root certificate authorities for the malicious certificate chain. These are useful if you need to do validation of the malicious_certificate.pem chain during testing.
* `author_name_regex.json`: An example JSON file with the C2PA_ATTACK keyword in the author's name field and id field. For unit testing, you would most likely want to only use field at a time. The use of two fields is just to demonstrate that it will replace all occurrences of the string with each pass. This can be used with a regex command line: `-t regex`. This is not the only way to inject into the author's name field. You could also do this by using test.json along with `-t author` in the command line. This file is just to demonstrate a regex-based approach on a common field. The value C2PA_ATTACK could be put into any of the JSON value field that needs testing.
* `trust_anchors.pem`:  A list of trust anchors (in PEM format) used to validate the manifest certificate chain. To be valid, the manifest certificate chain must lead to a certificate on the trust list. All certificates in the trust anchor list must have the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) and the CA attribute of this extension must be `True`.
* `store.cfg`: The trust store config with the allowed set of custom certificate extended key usages (EKUs). Each entry in the list is an object identifiers in [OID dot notation](http://www.oid-info.com/#oid) format.
* `allowed_list.pem`: A list of end-entity certificates (in PEM format) to trust. These certificates are used to sign the manifest. Supersedes the `trust_anchors` setting. The list must NOT contain certificates with the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) with the CA attribute `True`.