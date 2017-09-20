package main

import (
	"time"
)

const headerTemplateText = `
{{define "header"}}
<div class="header">
<table style="width:100%;">
<tr>
<th style="text-align:left;"> <div class="header_extra">{{template "header_extra"}}</div></th>
<th style="text-align:right;">  {{if .AuthUsername}} <b> {{.AuthUsername}} </b> <a href="/api/v0/logout" >Logout </a> {{end}}</th>
</tr>
</table>
</div>

{{end}}
`

const footerTemplateText = `
{{define "footer"}}

<div class="footer">
<hr>
<center>
Copright 2017 Symantec Corporation.  {{template "footer_extra"}}
</center>
</div>
{{end}}
`

type loginPageTemplateData struct {
	Title        string
	AuthUsername string
	JSSources    []string
	ShowOauth2   bool
	DocsURL      string
}

//Should be a template
const loginFormText = `
{{define "loginPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
	<link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
	<link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
        <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
    </head>
    <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
    <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">
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
	</div>
	{{template "footer" . }}
	</div>
    </body>
</html>
{{end}}
`

type secondFactorAuthTemplateData struct {
	Title        string
	AuthUsername string
	JSSources    []string
	ShowOTP      bool
	ShowU2F      bool
}

const secondFactorAuthFormText = `
{{define "secondFactorLoginPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
        {{if .JSSources -}}
        {{- range .JSSources }}
        <script type="text/javascript" src="{{.}}"></script>
        {{- end}}
        {{- end}}
        <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
        <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
        <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
    </head>
    <body>
        <div  style="min-height:100%;position:relative;">
	{{template "header" .}}
	<div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">
        <h2> Keymaster second factor Authenticaion </h2>
	{{if .ShowOTP}}
        <form enctype="application/x-www-form-urlencoded" action="/api/v0/vipAuth" method="post">
            <p>
	    Enter VIP token value: <INPUT TYPE="text" NAME="OTP" SIZE=18>
            <input type="submit" value="Submit" />
	    </p>
        </form>
	{{if .ShowU2F}}
	<p>
	<h4>Or</h4>
	</p>
	{{end}}
	{{end}}
	{{if .ShowU2F}}
	<p>
               <div id="auth_action_text" > Authenticate by touching a blinking registered U2F device (insert if not inserted yet)</div>
        </p>
	{{end}}
	</div>
	{{template "footer" . }}
	</div>
	</body>
</html>
{{end}}
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
	AuthUsername    string
	Username        string
	JSSources       []string
	ShowU2F         bool
	RegisteredToken []registeredU2FTokenDisplayInfo
}

//{{ .Date | formatAsDate}} {{ printf "%-20s" .Description }} {{.AmountInCents | formatAsDollars -}}
const profileHTML = `
{{define "userProfilePage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
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
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
    <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
    <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
  </head>
  <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
    <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">

    {{with $top := . }}
    <h1>Keymaster User Profile</h1>
    <h2> {{.Username}}</h2>
    <ul>
      <li><a href="/api/v0/logout" >Logout </a></li>
       {{if .ShowU2F}}
      <li>
         <a id="register_button" href="#">Register token</a>
         <div id="register_action_text" style="color: blue;background-color: yellow; display: none;"> Please Touch the blinking device to register(insert if not inserted yet) </div>
      </li>
      <li><a id="auth_button" href="#">Authenticate</a>
      <div id="auth_action_text" style="color: blue;background-color: yellow; display: none;"> Please Touch the blinking device to authenticate(insert if not inserted yet) </div>
      </li>
      {{else}}
      <div id="auth_action_text" style="color: blue;background-color: yellow;"> Your browser does not support U2F. However you can still Enable/Disable/Delete U2F tokens </div>
      {{end}}
    </ul>
    {{if .RegisteredToken -}}
        Your U2F Token(s):
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
    {{end}}
    </div>
    {{template "footer" . }}
    </div>
  </body>
</html>
{{end}}
`
