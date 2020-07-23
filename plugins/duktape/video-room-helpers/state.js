// @ts-check

/**@param {IGlobal} global
 * @returns {State}
*/
module.exports = function (global) {

  var util = require("./util")(global);

  var state = {
    janusServer: "webconf.yourcompany.net",
    /**@type {ISessions} */
    sessions: {},
    /** @type {ITasks} */
    tasks: [],
    // publishers: [],
    /**@type {IRooms} */
    rooms: {},
    /**@type {IManagerSessions} */
    managerSessions: {},
    /**
     * @param {number} roomId
     * @returns {IRoom}
     */
    getRoom: function (roomId) {
      var room = null;
      if (state.rooms[roomId]) {
        room = state.rooms[roomId];
      } else {
        // new room template
        var newRoomTemplate = { roomId: 0, roomName: "", managerSessionID: 0, publishers: [], sessions: [] };

        //
        /* util.startRoomHttpRequest({ server: "localhost", room_id: roomId, publisher_state: [] }); */
        //

        room = newRoomTemplate;
        room.roomId = roomId
        state.rooms[roomId] = room;
      }
      return room;
    },
    /**
     * @param {number} sessionID
     * @returns {ISession}
     */
    getSession: function (sessionID) {
      var session = null;
      if (state.sessions[sessionID]) {
        session = state.sessions[sessionID];
      } else {
        // Objects Templates
        var newSessionTemplate = { id: 0, janusServer: state.janusServer, room: 0, subscribers: [], publishers: [], isConnected: false };
        // new session template
        session = newSessionTemplate;
        session.id = sessionID;
        state.sessions[sessionID] = session;
        console.log("New session (" + sessionID + ") was burn !!!! ", session);
      }
      return session
    },
    /**
     * @param {ISession} session
     * @returns {void}
     */
    setSession: function (session) {
      state.sessions[session.id] = session;
      console.log("session (" + session.id + ") was updated!!!! ", session);
    },
    /**
     * @param {IRoom} room
     * @returns {void}
     */
    setRoom: function (room) {
      state.rooms[room.roomId] = room;
    },
  }

  return state;

}
