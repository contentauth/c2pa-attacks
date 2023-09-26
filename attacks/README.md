## Injection attack files

This directory contains files that you can use as the basis for injection attacks. The tool reads line-by-line from the file specified by the `-a` option and injects each line into a new malicious output image. 

These files contain only very basic injection techniques. They are not tuned for your software's technology stack.  Adapt them for your particular environment. 
If you are completely new to security testing, then the [OWASP testing guide](https://owasp.org/www-project-web-security-testing-guide/stable/) is a good place to start for testing web applications.

If you are looking for injections that you can copy and paste, then the [PayloadBox GitHub org](https://github.com/payloadbox) contains many repos with thousands of injection strings for cross-site-scripting, SQL injection, and more. The payloads for SQL Injection are grouped based on the type of database to help you find attack strings specific to your environment.

To inject really long strings for triggering buffer overflows, then it is easy to generate strings with some simple command lines. For exampl,e this command generates 100 'a' characters in the file `output_file.attack`:

```shell
printf 'a%.0s' {1..100} > output_file.attack
```

The `.gitattributes` maps the `.attack` filename extension to `binary` so that GitHub will persist binary characters in files with that extension.

## Files

This directory contains the following files:

- `xss.attack`: A few simple XSS injections.
- `ten_thousand_characters.attack`: A 10,000 character string to test for buffer overflows.
- `sql_injection.attack`: A few simple SQL injection techniques. 
- `rendering.attack`: A simple Hello World that contains newlines. This is to inspire people to test rendering techniques where someone might try to split what the person sees in their display because of injected newlines.
- `special_characters.attack`: A selection of special characters as a way to test special character handling in the UI.

 Refer to the [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) or the [PayloadBox GitHub repo](https://github.com/payloadbox) for more advanced techniques.


