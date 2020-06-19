# Open redirect

##What is it?
Manipulating the redirect_to parameter to an evil site.
Open redirects exploit the trust of a given domain.

##How to search for it?
Look for a GET request sent to the site you're testing with a parameter specifying a URL to redirect to.

Note-
1. Redirect parameters might not always be labeled.
2. DNS lookups look at the right most domain.

##Simple redirect -
www.example.com?checkout=acttacker.com

##Interstitial Redirect -
Interstitial web page is one showed before expected content.

As we search for these vulnerabilities. take note of different services they're using like Zendesk
as they may allow for redirects.

Redirect parameters are sometimes easy to spot with names like 'redirect_to=', 'domain_-
name=', 'checkout_url=', and so on. Whereas other times they may have less obvious
names like r=, u=, and so on.

## Using Burp to test for Open redirects

1. Intercept the traffic
2. Send the request to Spider
3. Under Target > Site Map > Filter > 3xx Redirect
4. Look for interesting url parameters and edits values using repeater
