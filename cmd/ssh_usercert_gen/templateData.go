package main

import (
	"time"
)

//Should be a template
const loginFormText = `
<!DOCTYPE html>
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

type registeredU2FTokenDisplayInfo struct {
	RegistrationDate time.Time
	DeviceData       string
	Name             string
	Index            int
	Enabled          bool
}
type profilePageTemplateData struct {
	Title           string
	Username        string
	JSSources       []string
	RegisteredToken []registeredU2FTokenDisplayInfo
}

//{{ .Date | formatAsDate}} {{ printf "%-20s" .Description }} {{.AmountInCents | formatAsDollars -}}
const profileHTML = `<!DOCTYPE html>
<html>
  <head>
    <title>{{.Title}}</title>
    {{if .JSSources -}}
    {{- range .JSSources }}
    <script type="text/javascript" src="{{.}}"></script>
    {{- end}}
    {{- end}}
    <!-- The original u2f-api.js code can be found here:
    https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js -->
    <!-- script type="text/javascript" src="https://demo.yubico.com/js/u2f-api.js"></script-->
  </head>
  <body>
    {{with $top := . }}
    <h1>FIDO U2F Go Library Demo</h1>
    <h2> {{.Username}}</h2>
    <ul>
      <li><a href="javascript:register();">Register token</a></li>
      <li><a href="javascript:sign();">Authenticate</a></li>
    </ul>
    {{if .RegisteredToken -}}
        Your Token(s):
        <table>
	    <tr>
	    <th>Name</th>
	    <th>Device Data</th>
	    <th>Actions</th>
	    </tr>
	    {{- range .RegisteredToken }}
            <tr>
	     <form enctype="application/x-www-form-urlencoded" action="/api/v0/manageU2FToken" method="post">
	     <input type="hidden" name="index" value="{{.Index}}">
	     <input type="hidden" name="username" value="{{$top.Username}}">
	     <td> <input type="text" name="name" value="{{ .Name}}" SIZE=18 > </td>
	     <td> {{ .DeviceData}} </td>
	     <td>
	         <input type="submit" name="action" value="Update" {{if not .Enabled}} disabled {{end}}/>
		 {{if .Enabled}}
		 <input type="submit" name="action" value="Disable"/>
		 {{ else }}
		 <input type="submit" name="action" value="Enable"/>
		 <input type="submit" name="action" value="Delete" {{if .Enabled}} disabled {{end}}/>
		 {{ end }}
	     </td>
	     </form>
	     </tr>
	    {{- end}}
	</table>
    {{- else}}
	You Dont have any registered tokens.
    {{- end}}
    <p>Open Chrome Developer Tools to see debug console logs.</p>
    {{end}}
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
      location.reload();
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
