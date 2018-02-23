/*
function serverError(data) {
    console.log(data);
    alert('Server error code ' + data.status + ': ' + data.responseText);
  }

function checkError(resp) {
    if (!('errorCode' in resp)) {
      return false;
    }
    //if (resp.errorCode === u2f.ErrorCodes['OK']) {
    if (resp.errorCode == 0) {
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
  
  function u2fSigned(resp) {
    document.getElementById('auth_action_text').style.display="none";
    //console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/u2f/SignResponse', JSON.stringify(resp)).success(function() {
      //alert('Success');
      var destination = document.getElementById("u2f_login_destination").innerHTML;
      window.location.href = destination;
    }).fail(serverError);
  }
  function signXXXX() {
     document.getElementById('auth_action_text').style.display="block";
    $.getJSON('/u2f/SignRequest').success(function(req) {
      console.log(req);
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 30);
    }).fail(serverError);
  }
  */
  function singleVipPoll() {
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
              // Action to be performed when the document is read;
              var destination = document.getElementById("vip_login_destination").innerHTML;
              window.location.href = destination;
          }
      };
      xhr.open("GET", "/api/v0/vipPollCheck", true);
      xhr.send();   
  }

  function startVipPoll() {
      console.log("start of vip poll");
      poller = setInterval(singleVipPoll, 3000);
      var startPushButton = document.getElementById("start_vip_push_button")
      if (startPushButton) {
          startPushButton.addEventListener('click', startVipPush, false);
      } else {
	  startVipPush();
      }
      setTimeout(clearInterval,60000, poller)
  }
  function startVipPush() {
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
              // Action to be performed when the document is read;
              //var destination = document.getElementById("vip_login_destination").innerHTML;
              //window.location.href = destination;
              cosole.log("success vip push start")
          }
      };
      xhr.open("GET", "/api/v0/vipPushStart", true);
      xhr.send();   
  }

document.addEventListener('DOMContentLoaded', function () {
	  //document.getElementById('auth_button').addEventListener('click', sign);
	  startVipPoll();
});
