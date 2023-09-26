## Injection attack files

This directory contains files that you can use as the basis for injection attacks. The tool reads line-by-line from the file specified by the `-a` option and injects each line into a new malicious output image. These files contain only very basic injection techniques.  Adapt them for your target environment and technology stack. 

Refer to the [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) and the [PayloadBox GitHub repo](https://github.com/payloadbox) for more techniques and related information.

## Files

This directory contains the following files:

- `xss.attack`: A few simple XSS injections.
- `ten_thousand_characters.attack`: A 10,000 character string to test for buffer overflows.
- `sql_injection.attack`: A few simple SQL injection techniques. 
- `rendering.attack`: A simple "Hello World" attack that contains newlines to inspire testing rendering techniques that split the UI display with injected newlines.
- `special_characters.attack`: A selection of special characters as a way to test special character handling in the UI.

 NOTE: The `.gitattributes` file in this directory maps the `.attack` filename extension to `binary` so that GitHub will persist binary characters in those files.

## Generating long strings

To inject really long strings for triggering buffer overflows, it is easy to generate strings with some simple command lines. For exampl,e this command generates 100 'a' characters in the file `output_file.attack`:

```shell
printf 'a%.0s' {1..100} > output_file.attack
```

## Resources and more information

For a large set of injections that you can copy and paste, see the [PayloadBox GitHub org](https://github.com/payloadbox), which contains repos with many injection strings for cross-site-scripting, SQL injection, and more. The payloads for SQL injection are grouped based on the type of database to help you find attack strings specific to your environment.





