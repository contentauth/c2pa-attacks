# Appendix

## C2PA references

The "c2patool" is a good complimentary tool for inspecting the files created by this tool: [https://github.com/contentauth/c2pa-rs/tree/main/cli](https://github.com/contentauth/c2pa-rs/tree/main/cli).

Technical specifications for C2PA standard assertions including JSON samples: [https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_c2pa_standard_assertions](https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_c2pa_standard_assertions).

## Injection string references

OWASP Overview of cross-site scripting with links on how to test on the different forms of cross-site scripting: <https://owasp.org/www-community/attacks/xss/>.

OWASP Testing Guide section on SQL Injection: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection>.

The4 PayloadBox GitHub Repo has a collection of injection strings: <https://github.com/payloadbox>.

Another possibility for injection strings is prompt injection attacks. They are not currently included as sample strings because they are often specific to the AI that is reading the data. However, if your organization builds AI that is intended to read C2PA metadata, you could use this tool to create assets with prompt injections tailored to your AI solution for testing.

## Additional baseline test case files

For sample file types beyond JPEGs for testing, the C2PA maintains a list of sample files here: <https://github.com/c2pa-org/public-testfiles>.

## Creating and using an X.509 certificate

If you want to create your own certificate authority, C2PA members can see the OpenSSL commands in <https://opensource.contentauthenticity.org/docs/c2pa-python-example/#for-development-using-self-signed-certificates/>.

Rather than generating your own certificates, you can also test creating your own manifests using provided pre-built certificates; see [Creating and using an X.509 certificate](https://opensource.contentauthenticity.org/docs/c2patool/docs/x_509) for more information.
