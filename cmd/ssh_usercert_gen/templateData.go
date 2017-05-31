package main

//Should be a template
const loginFormText = `
<html>
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
    </head>
    <body>
        <form enctype="application/x-www-form-urlencoded" action="/api/v0/login" method="post">
            <p>Username: <INPUT TYPE="text" NAME="username" SIZE=18></p>
            <p>Password: <INPUT TYPE="password" NAME="password" SIZE=18></p>
            <p><input type="submit" value="Submit" /></p>
        </form>
    </body>
</html>
`

const indexHTML = `<!DOCTYPE html>
<html>
  <head>
    <script src="//code.jquery.com/jquery-1.12.4.min.js"></script>
    <!-- The original u2f-api.js code can be found here:
    https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js -->
    <script type="text/javascript" src="/static/u2f-api.js"></script>
    <!-- script type="text/javascript" src="https://demo.yubico.com/js/u2f-api.js"></script-->
  </head>
  <body>
    <h1>FIDO U2F Go Library Demo</h1>
    <ul>
      <li><a href="javascript:register();">Register token</a></li>
      <li><a href="javascript:sign();">Authenticate</a></li>
    </ul>
    <p>Open Chrome Developer Tools to see debug console logs.</p>
    <script>
  function serverError(data) {
    console.log(data);
    alert('Server error code ' + data.status + ': ' + data.responseText);
  }
  function checkError(resp) {
    if (!('errorCode' in resp)) {
      return false;
    }
    if (resp.errorCode === u2f.ErrorCodes['OK']) {
      return false;
    }
    var msg = 'U2F error code ' + resp.errorCode;
    for (name in u2f.ErrorCodes) {
      if (u2f.ErrorCodes[name] === resp.errorCode) {
        msg += ' (' + name + ')';
      }
    }
    if (resp.errorMessage) {
      msg += ': ' + resp.errorMessage;
    }
    console.log(msg);
    alert(msg);
    return true;
  }
  function u2fRegistered(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/u2f/RegisterResponse', JSON.stringify(resp)).success(function() {
      alert('Success');
    }).fail(serverError);
  }
  function register() {
    $.getJSON('/u2f/RegisterRequest').success(function(req) {
      console.log(req);
      u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 30);
    }).fail(serverError);
  }
  function u2fSigned(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/u2f/SignResponse', JSON.stringify(resp)).success(function() {
      alert('Success');
    }).fail(serverError);
  }
  function sign() {
    $.getJSON('/u2f/SignRequest').success(function(req) {
      console.log(req);
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 30);
    }).fail(serverError);
  }
    </script>
  </body>
</html>
`
