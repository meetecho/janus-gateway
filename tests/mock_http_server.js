http = require('http');
fs = require('fs');
server = http.createServer( function(req, res) {

  // console.log(req.headers);

  if (req.method == 'POST') {
    console.log("POST");
    var body = '';
    req.on('data', function (data) {
      body += data;
    });
    req.on('end', function () {
      console.log("Body: " + body);
      res.writeHead(200, {'Content-Type': 'text/json'});
      // echo back
      res.end(body);
    });
  }
  else
  {
    console.log("GET");
    var html = "";
    if(req.headers['foobar']){
      html = '<html><body>' + req.headers['foobar'] + '</body></html>';
    } else {
      html = '<html><body></body></html>';
    }
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(html);
  }

});

port = 3838;
host = '127.0.0.1';
server.listen(port, host);
console.log('Listening at http://' + host + ':' + port);