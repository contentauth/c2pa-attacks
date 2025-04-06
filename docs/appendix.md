# Appendix

## C2PA references

The "c2patool" is a good complimentary tool for inspecting the files created by this tool: <https://github.com/contentauth/c2patool>.

Technical specifications for C2PA standard assertions including JSON samples: <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_standard_assertions>.

## Injection string references

OWASP Overview of cross-site scripting with links on how to test on the different forms of cross-site scripting: <https://owasp.org/www-community/attacks/xss/>.

OWASP Testing Guide section on SQL Injection: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection>.

The4 PayloadBox GitHub Repo has a collection of injection strings: <https://github.com/payloadbox>.

## Additional baseline test case files

For sample file types beyond JPEGs for testing, the C2PA maintains a list of sample files here: <https://github.com/c2pa-org/public-testfiles>.

## Creating and using an X.509 certificate

If you want to create your own certificate authority, C2PA members can see the OpenSSL commands in <https://opensource.contentauthenticity.org/docs/c2pa-python-example/#for-development-using-self-signed-certificates/>.

Rather than generating your own certificates, you can also test creating your own manifests using provided pre-built certificates; see [Creating and using an X.509 certificate](https://opensource.contentauthenticity.org/docs/c2patool/docs/x_509) for more information.