module.exports = function (global) {
  var util = {
    serialize: function(obj, prefix) {
      var str = [],
        p;
      for (p in obj) {
        if (obj.hasOwnProperty(p)) {
          var k = prefix ? prefix + "[" + p + "]" : p,
            v = obj[p];
          str.push((v !== null && typeof v === "object") ?
            serialize(v, k) :
            encodeURIComponent(k) + "=" + encodeURIComponent(v));
        }
      }
      return str.join("&");
    },
    get: function(url) {
      return global.http_get(url);
    },
    post: function(url, body) {
      return global.http_post(url, util.serialize(body));
    }
  }

  return util;
}
