package main

import (
	"time"
)

type loginPageTemplateData struct {
	Title      string
	JSSources  []string
	ShowOauth2 bool
}

//Should be a template
const loginFormText = `
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
	<style>body{margin:1em auto;max-width:80em;padding:0 .62em;font-family: sans-serif;}h1,h2,h3{line-height:1.2;}@media print{body{max-width:none}}</style>
    </head>
    <body>
        <h2> Keymaster Login </h2>
	{{if .ShowOauth2}}
	<p>
	<a href="/auth/oauth2/login"> Oauth2 Login </a>
	</p>
        {{end}}
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
	Index            int64
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
     <style>body{margin:1em auto;max-width:80em;padding:0 .62em;font-family: sans-serif;}h1,h2,h3{line-height:1.2;}@media print{body{max-width:none}}</style>
  </head>
  <body>
    {{with $top := . }}
    <h1>Keymaster User Profile</h1>
    <h2> {{.Username}}</h2>
    <ul>
      <li><a href="/api/v0/logout" >Logout </a></li>
      <li>
         <a id="register_button" href="#">Register token</a>
         <div id="register_action_text" style="color: blue;background-color: yellow; display: none;"> Please Touch the blinking device to register(insert if not inserted yet) </div>
      </li>
      <li><a id="auth_button" href="#">Authenticate</a>
      <div id="auth_action_text" style="color: blue;background-color: yellow; display: none;"> Please Touch the blinking device to authenticate(insert if not inserted yet) </div>
      </li>
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
  </body>
</html>
`
