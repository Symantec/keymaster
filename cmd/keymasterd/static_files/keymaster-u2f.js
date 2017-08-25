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
    document.getElementById('register_action_text').style.display="block";
    $.getJSON('/u2f/RegisterRequest').success(function(req) {
      console.log(req);
      u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 30);
    }).fail(serverError);
  }
  function u2fSigned(resp) {
    document.getElementById('auth_action_text').style.display="none";
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/u2f/SignResponse', JSON.stringify(resp)).success(function() {
      alert('Success');
    }).fail(serverError);
  }
  function sign() {
     document.getElementById('auth_action_text').style.display="block";
    $.getJSON('/u2f/SignRequest').success(function(req) {
      console.log(req);
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 30);
    }).fail(serverError);
  }

document.addEventListener('DOMContentLoaded', function () {
	  document.getElementById('auth_button').addEventListener('click', sign);
	  document.getElementById('register_button').addEventListener('click', register);
	  //  main();
});
