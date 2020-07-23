// @ts-check

/**@param {Global} global */
module.exports = function (global) {

  var util = require("./util")(global);

  var state = {
    janusServer: "webconf.yourcompany.net",
    sessions: {},
    tasks: [],
    publishers: [],
    rooms: {},
    managerSessions: {},
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
    setSession: function (session) {
      state.sessions[session.id] = session;
      console.log("session (" + session.id + ") was updated!!!! ", session);
    },
    setRoom: function (room) {
      state.rooms[room.roomId] = room;
    },
  }

  return state;

}
