## Injection attack files

This directory contains files that can be used as the basis for the injection attacks. The file that is specified by the command line argument `-a` will be read line by line. Each line in the file will be injected into a new malicious output image. These files contain only very basic injection techniques. They are probably not tuned for your software's technology stack. It is expected that the person running this tool will adapt these files for their particular environment. If you are completely new to security testing, then the OWASP testing guide is a good place to start for anyone testing web applications: https://owasp.org/www-project-web-security-testing-guide/stable/.

If you are looking for a GitHub repo of injections that you can copy and paste, then this repo contains thousands of injection strings for cross-site-scripting, SQL injection, and more: https://github.com/payloadbox/. The payloads for SQL Injection are grouped based on the type of database. This will allow you to find attack strings specific to your environment.

If you want to inject really long strings for triggering buffer overflows, then it is easy to generate strings with some simple command lines. This will generate 100 'a' characters in output_file.attack:

```shell
printf 'a%.0s' {1..100} > output_file.attack
```

The `.gitattributes` maps the `.attack` filename extension to `binary` so that GitHub will persist binary characters in files with that extension.

## Files

### Attacks directory (/attacks)

- xss.attack: A few simple XSS injections. Refer to the OWASP Testing Guide or the PayloadBox GitHub repo for more advanced techniques.
- ten_thousand_characters.attack: A 10,000 character string to test for buffer overflows
- sql_injection.attack: A few simple SQL injection techniques. Refer to the OWASP Testing Guide or the PayloadBox GitHub repo for more advanced techniques.
- rendering.attack: A simple Hello World that contains newlines. This is to inspire people to test rendering techniques where someone might try to split what the person sees in their display because of injected newlines.
- special_characters.attack: A selection of special characters as a way to test special character handling in the UI.

### Sample directory (/sample)

- malicious_certificate.key and malicious_certificate.pem - These are a certificate / key pair with random characters in the common name, organization, and organizational unit fields for testing a certificate parser's capability to unhandled unexpected characters. These are from a self-signed CA, so they should not work on an environment that is enforcing a trusted CA list.
- malicious_certificate.json - This is a manifest that is the same as test.json except that it specifies to use the malicious certificates for signing.
