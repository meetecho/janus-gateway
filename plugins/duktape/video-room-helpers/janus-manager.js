// @ts-check

/** 
 * @param {IGlobal} global
 * @param {IState} state 
 * */
module.exports = function (global, state) {

  var util = require("./util")(global);

  /** @param {IRoomInfo} roomInfo */
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

  /** @param {IRoomInfo} roomInfo */
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