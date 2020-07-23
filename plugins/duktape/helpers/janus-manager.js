// @ts-check

/** 
 * @param {Global} global
 * @param {State} state 
 * */
module.exports = function (global, state) {

  var util = require("./util")(global);

  /** @param {RoomInfo} roomInfo */
  function connectToManager(roomInfo) {

  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {IBody} body
   * */
  function handleManagerMessage(id, tr, body) {
    switch (body.request) {
      case "join":
        return handleJoinManager(id, tr, body);
      case "sync":
        return handleSyncManager(id, tr, body);
    }
    return 1;
  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {IBody} body
   * */
  function handleJoinManager(id, tr, body) {
    return 1;
  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {IBody} body
   * */
  function handleSyncManager(id, tr, body) {
    return 1;
  }

  /** @param {RoomInfo} roomInfo */
  function syncRoomToManager(roomInfo) {

  }

  return {
    connectToManager,
    handleManagerMessage,
    handleJoinManager,
    handleSyncManager,
    syncRoomToManager
  }
}