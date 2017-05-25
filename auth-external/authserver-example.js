//
// Whhat port to listen on
//
var PORT = 3000;

//
// Configure (in this example, hard-coded) allowed tokens and their authorizations
//
var allowedTokens =
{
  // Token 'default' is only allowed the "standard" stuff, e.g., 
  // not plugin-specific, or "trickle".
  default : function(request)
  {
    var authenticated = allowStandard(request);
    return authenticated;
  },

  // Token 'echoonly' is only allowed access to the echo plugin (and the "standard" stuff)
  echoonly : function(request)
  {
    var authenticated;

    // Default to disallowing all requests
    authenticated = allowStandard(request);

    // Allow specific requests to the streaming plugin
    if (request.plugin_package == "janus.plugin.echo")
    {
      authenticated = true;
    }

    return authenticated;
  },

  // Token 'restricted' is only allowed the following:
  //   - Access to the streaming plugin's "list" and "start" requests;
  //   - Access to the streaming plugin's "watch" request if the requested id is 999
  //   - Complete access to the echo plugin
  restricted : function(request)
  {
    var             authenticated;

    // Default to disallowing all requests
    authenticated = allowStandard(request);

    // Allow specific requests to the streaming plugin
    if (request.plugin_package == "janus.plugin.streaming" &&
        request.janus == "message")
    {
      // Allow streaming video 999
      if (request.body.request == "watch" && request.body.id == "999")
      {
        authenticated = true;
      }

      // Allow the "list" and "start" commands
      if ( [ "list", "start" ].indexOf(request.body.request) != -1)
      {
        authenticated = true;
      }
    }

    // Allow requests to the echo plugin
    if (request.plugin_package == "janus.plugin.echo")
    {
      authenticated = true;
    }

    return authenticated;
  },

  // Token 'superuser' is granted unlimited access.
  superuser : function(request)
  {
    return true;
  }
};

// Prepare to create a web server
var express = require('express');
var bodyParser = require("body-parser");

var app = express();

app.use(bodyParser.json());

// Authenticate when we receive a root-level POST request
app.post(
  "/",
  function(req, res)
  {
    var             request = req.body;
    var             authenticated = false;

    console.log("authserver got request:\n" + JSON.stringify(request, null, "  "));

    // Is this token recognized?
    if (typeof allowedTokens[request.token] == "function")
    {
      // Yup. Authenticate/authorize based on the request and token
      authenticated = allowedTokens[request.token](request);
    }
    console.log("authserver: " + (authenticated ? "allowed" : "not allowed"));

    // Send back the result
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(
      JSON.stringify(
        {
          authenticated : authenticated
        }));
  });

// Initialize immediately.
var port = PORT;
app.listen(port);
console.log('Listening at http://localhost:' + port)


//
// Allow the standard requests that any valid token likely wants
//
function allowStandard(request)
{
  var authenticated = false;

  // Allow trickle requests
  if (request.janus == "trickle")
  {
    authenticated = true;
  }

  // Allow any request that's not to a specific plugin
  if (! request.plugin_package)
  {
    authenticated = true;
  }

  return authenticated;
}
