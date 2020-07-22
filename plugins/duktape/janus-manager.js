/** @param {State} state */
module.exports = function (global, state) {

  var util = require("./util")(global);

  /** @param {RoomInfo} roomInfo */
  function connectToManager(roomInfo) {

  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {string} msg
   * */
  function handleManagerMessage(id, tr, msg) {

  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {string} msg
   * */
  function handleJoinManager(id, tr, msg) {

  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {string} msg
   * */
  function handleSyncManager(id, tr, msg) {

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