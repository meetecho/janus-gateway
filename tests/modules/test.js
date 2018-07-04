function request(url, body, headers) {
  var chunks = [];
  var outHeaders = {};
  var length = 0;
  var end = false;

  http.setopt("useragent", "DukLuv libcurl bindings");
  http.setopt("url", url);
  http.setopt("followlocation", true);

  http.setopt("writefunction", function (chunk) {
    var data = "";
    for (var i=0; i<chunk.byteLength; i++) {
      data += String.fromCharCode(chunk[i]);
    }
    chunks.push(data);
    length += data.length;
    return data.length;
  });

  http.setopt("headerfunction", function (header) {
    var length = header.length;
    header = header.toString();
    if (end) {
      // Only remember headers for last response.
      end = false;
      outHeaders = {};
    }
    if (header === "\r\n") {
      end = true;
    }
    var match = header.toString().match(/^([^:]+): *([^\r]+)/);
    if (match) {
      outHeaders[match[1].toLowerCase()] = match[2];
    }
    return length;
  });

  if (body) {
    headers = headers || [];
    headers.push("Content-Type: application/json");
    body = JSON.stringify(body) + "\n";
    headers.push("Content-Length: " + body.length);
    http.setopt("infilesize", body.length);
    http.setopt("readfunction", function (size) {
      if (!body) { return ""; }
      var chunk;
      if (body.length < size) {
        chunk = body;
        body = "";
        return chunk;
      }
      throw new Error("TODO: handle large file uploads");
    });
  }

  if (headers) {
    http.setopt("httpheader", headers);
  }

  http.perform();

  try { body = JSON.parse(chunks.join("")) } catch (error) { body = chunks.join("") };
  return {
    code: http.getinfo("response-code"),
    headers: outHeaders,
    body: body
  };
}

function get(url, headers) {
  http.reset();
  http.setopt("httpget", true);
  return request(url, null, headers);
}

function put(url, body, headers) {
  http.reset();
  http.setopt("put", true);
  return request(url, body, headers);
}

function post(url, body, headers) {
  http.reset();
  http.setopt("post", true);
  return request(url, body, headers);
}

var http = curl();



exports.test_duktape_extra_curl_loads = function(){
  http.reset();
  return "awesome";
}
exports.test_duktape_extra_curl_constructor_ignores_params = function(){
  http.reset();

  var response;
  // curl is just a construct so params don't matter
  try { 
    response = curl(1,2,3,4,5,6);
  } catch(error) {
    response = error.message;
  };
  return response;
}
exports.test_duktape_extra_curl_success = function(){
  http.reset();

  var response = get("http://localhost:3838");
  return JSON.stringify(response);
}
exports.test_duktape_extra_curl_headers = function(){
  http.reset();

  var response = get("http://localhost:3838", ['FooBar: foobar']);
  return JSON.stringify(response);

}
exports.test_duktape_extra_curl_post = function(){
  http.reset();

  var response = post("http://localhost:3838", {foo: 'bar'});
  return JSON.stringify(response.body);
}
