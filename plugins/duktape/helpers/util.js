// @ts-check

/** @param {Global} global */
module.exports = function (global) {
  var util = {
    serialize: function (obj, prefix) {
      var str = [],
        p;
      for (p in obj) {
        if (obj.hasOwnProperty(p)) {
          var k = prefix ? prefix + "[" + p + "]" : p,
            v = obj[p];
          str.push((v !== null && typeof v === "object") ?
            util.serialize(v, k) :
            encodeURIComponent(k) + "=" + encodeURIComponent(v));
        }
      }
      return str.join("&");
    },
    /** @param {string} url */
    get: function (url) {
      return global.http_get(url);
    },
    /** 
     * @param {string} url
     * @param {{[key:string]: any}} body
     * */
    post: function (url, body) {
      return global.http_post(url, util.serialize(body));
    },
    /**@param {IJanusHTTPBody} body  */
    startRoomHttpRequest: function(body) {
      return util.post("http://localhost:3000/start-room", body);
    }
  }

  return util;
}

