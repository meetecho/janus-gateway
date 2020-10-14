// @ts-check

/**@param {IGlobal} global
 * @returns {IState}
*/
module.exports = function (global) {

  var util = require("./util")(global);

  /**@type {IState} */
  var state = {
    janusServer: "webconf.yourcompany.net",
    sessions: {},
    tasks: [],
    // publishers: [],
    rooms: {},
    managerSessions: {},
    getRoom: function (roomId) {
      var room = null;
      if (state.rooms[roomId]) {
        room = state.rooms[roomId];
      }
      return room;
    },
    newRoom: function (roomId) {
        var room = null;
        // new room template
        var newRoomTemplate = { roomId: roomId, roomName: "", managerSessionID: 0, publishers: [], sessions: [] };

        console.log('requesttt' , newRoomTemplate)

        //
        /* util.startRoomHttpRequest({ server: "localhost", room_id: roomId, publisher_state: [] }); */
        //

        room = newRoomTemplate;
        //room.roomId = roomId
        state.rooms[roomId] = room;      
        return room
    },
    deleteSession: function(sessionID){
      var session = state.sessions[sessionID]
      console.log('Session deleted ', session.id , session.type)
      delete state.sessions[sessionID] 
    },
    getSession: function (sessionID) {
      var session = null;
      var debugSessionsArray = []
      for( var debugSessions in state.sessions ){
        debugSessionsArray.push(debugSessions)
      }
      console.log('AllSessions',JSON.stringify(debugSessionsArray))

      if (state.sessions[sessionID]) {
        session = state.sessions[sessionID];
      } 
      
      return session
    },
    newSession: function (sessionID) {
      console.log('sessiones new', sessionID)
      var session = null;
        // Objects Templates
        /**@type {ISession} */
        var newSessionTemplate = { id: 0, janusServer: state.janusServer, room: 0, subscribers: [], publishers: [], isConnected: false, display: "", state: {} };
        // new session template
        session = newSessionTemplate;
        session.id = sessionID;
        state.sessions[sessionID] = session;
        console.log("New session (" + sessionID + ") was burn !!!! ", session, state.sessions);
        return session
    },
    setSession: function (session) {
      

      state.sessions[session.id] = session;
      console.log("session (" + session.id + ") was updated!!!! ", session);
    },
    setRoom: function (room) {
      state.rooms[room.roomId] = room;
    },
    deleteRoom(roomID){
      var room = state.rooms[roomID]
      console.log('Room deleted ', room.roomId , room.roomName)
      delete state.rooms[roomID]
    },
    getRoomPublishers: function (roomId, filterPublisher) {
      /**@type {ISessions} */
      var roomPublishersObj = {};
      var room = state.getRoom(roomId);
      room.publishers.forEach(function (publisher) {
        if (publisher !== filterPublisher) roomPublishersObj[publisher] = state.sessions[publisher];
      });
      return roomPublishersObj;
    },
    getRoomPublishersArray: function (roomId, filterPublisher) {
      /**@type {Array<ISession>}*/
      var pulisherArray = [];
      console.log('getRoomPublishersArray ',roomId )
      var room = state.getRoom(roomId);
      console.log('getRoomPublishersArray',room.publishers)
      if (room.publishers) {
        room.publishers.forEach(function (publisher) {
          if (publisher !== filterPublisher) pulisherArray.push(state.sessions[publisher]);
        });
      }
      return pulisherArray;
    }
  }

  return state;

}
