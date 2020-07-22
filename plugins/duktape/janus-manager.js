/** @param {State} state */
module.exports = function (global, state) {

  var util = require("./util")(global);

  /** @param {RoomInfo} roomInfo */
  function connectToManager(roomInfo) {

  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {Body} body
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
   * @param {Body} body
   * */
  function handleJoinManager(id, tr, body) {
    return 1;
  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {Body} body
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

/**
 * @typedef {{
  audioCodec: string,
  display: string,
  id: number,
  isConnected: boolean,
  janusServer: string,
  private_Id: number,
  publishers: Array<any>,
  room: number,
  subscribers: Array<any>,
  videoCodec: string,
  }} PublisherItem
 * */

/** @typedef {{room_id: number, server: string, publisher_list: Array<PublisherItem>}} RoomInfo */

/**
 * @typedef {{
    sessions: {};
    tasks: any[];
    publishers: any[];
    rooms: {};
    managerSessions: {};
    getRoom: (roomId: any) => any;
    getSession: (sessionID: any) => any;
    setSession: (session: any) => void;
    setRoom: (room: any) => void;
}} State
 */

/**
 * @typedef {{
       meetingID: number;
       sessionID: number;
       handleID: number;
       request: string;
       ptype: string;
     }} Body
 */