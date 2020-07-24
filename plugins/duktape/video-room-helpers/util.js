// @ts-check

/** @param {IGlobal} global */
module.exports = function (global) {
  var util = {
    /**
     * @param {number} min 
     * @param {number} max 
     */
    getRndInteger: function (min, max) {
      return Math.floor(Math.random() * (max - min + 1)) + min;
    },
    /**@param {number} [len] */
    genRandString: function (len) {
      if (!len) {
        len = 10;
      }

      var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      var output = "";

      for (var i = 0; i < len; i++) {
        output += chars[util.getRndInteger(0, chars.length - 1)];
      }

      return output;
    },
    /**@returns {string} */
    serialize: function (obj, prefix) {
      var str = [], p;
      for (p in obj) {
        if (obj.hasOwnProperty(p)) {
          var k = prefix ? prefix + "[" + p + "]" : p, v = obj[p];
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
    /** @param {IRoomInfo} body */
    startRoomHttpRequest: function (body) {
      var domain = "localhost:3000";
      return util.post("http://" + domain + "/start-room", body);
    }
  }

  return util;
}

