# HTML Injection

If a website renders the HTML put into a field then it maybe vulnerable.
Input is not sanitized

## Example -

URL encode `<h1> test </h1>` and paste and see if it is rendered and how the website handles it.

`http://127.0.0.1/htmli.php?nickname=``<h1>test</h1>`'`
`http://127.0.0.1/htmli.php?nickname=%3Cimg%20src=http://google.com%20img%3E`


## HTML Injection inside tag Attributes

Say there is a hidden field on the page and you can change it's query values which is passed on Input

`http://127.0.0.1/htmltagsi.php?sid=1`

There is no change to the page visibly

`?sid=<h1>test</h1>`

Basically we can escape and create our own tag.
`http://127.0.0.1/htmltagsi.php?sid=%22%3E%3Ch1%3Etest%3C/h1%3E`

We can create false forms or fields and point to our machine.

## HTML injection  using 3rd party data resources

Say a input field accepts a URL to fetch the page title.
Now if we can create something like `<html><title><h1>test</h1></title.</html>`
this is not allowed and will render the h1 part as text. however if the fetching field is not sanitizing input then we can have it render here instead.

## Bypass filters Cgi.Escape

cgi.escape is commonly use to escape html in input.

### Test -
`'
#python
import cgi
user_input="<h1>vulnerable</h1>"
`'
If we run `cgi.escape(user_input)` we get a response where the `<` turns into `&lt;`

By default the single quote is not escaped so we can use '"'
Using `cgi.escape(user_input,  quote=true)` will escape double quotes.

Say we enter <>&"' and see what happens, if the double quotes are not escaped we see they are generally not rendered and if we see the source we see the following -

`<input type="text" value="&gt;&lt;&amp;"'" class="input-block-level" placeholder="Email address" name="email">`
Where the mishandling of quotes is evident.

Now we can't easily put tags etc. because we can't use < or >. so we use eventlisteners
`sample" onmouseover="alert('xss');`

## Interesting

Always keep an eye on URL parameters and if they're reflected back on the page.
