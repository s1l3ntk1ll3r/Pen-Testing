# CRLF injection

## Description
CRLF injection occurs when an application doesn't sanitize input correctly and allows for carriage returns and line feeds.

The effect of a
CRLF Injection includes HTTP Request Smuggling and HTTP Response Splitting.
HTTP Request Smuggling occurs when an HTTP request is passed through a server
which processes it and passes it to another server, like a proxy or firewall. This type
of vulnerability can result in:
• Cache poisoning, a situation where an attacker can change entries in an application’s
cache and serve malicious pages (e.g., containing JavaScript) instead of a
proper page
• Firewall evasion, where a request can be crafted using CRLFs to avoid security
checks
• Request Hijacking, a situation where an attacker can steal HttpOnly cookies and
HTTP authentication information. This is similar to XSS but requires no interaction
between the attacker and client


HTTP Response Splitting, however, allows an attacker to insert HTTP response headers
and potentially control HTTP response bodies or split the response entirely, effectively
creating two separate responses. This is effective because modifying HTTP headers can
result in unintended behavior, such as redirecting a user to an unexpected website or
serving explicitly new content controlled by attackers.

### Interesting stuff :
When you are looking for vulnerabilities, always remember to think outside the
box and submit encoded values to see how the site handles the input.

Be on the lookout for opportunities where a site is accepting your input and using
it as part of its return headers, particularly setting cookies. This is particularly
significant when it occurs via a GET request as less interaction from the victim is
required.

`%0D%0A`
are particularly significant characters as they can lead to CRLF Injection issues. When
hacking, be on the lookout for parameters that are potentially attacker controlled but
being reflected back in a HTTP header. If they are, start testing the site for their handling
of encoded characters, particularly %0D%0A. If successful, try to take it a step further
and combine the vulnerability with a XSS injection for an impactful proof of concept.
On the other hand, if the server doesn’t respond to %0D%0A think about how you could
double encode these characters, passing in %250D or adding 3 byte characters in the
event the site is mishandling the extra values.
