var sessions = {};
var tasks = [];
var publishers = [];
var rooms = {};
var managerSessions = {};

function getRoom(roomId) {
	var room = null;
	if (rooms[roomId]) {
		room = rooms[roomId];
	} else {
		// new room template
		var newRoomTemplate = { roomId: 0, roomName: "", managerSessionID: 0, publishers: [], sessions: [] };

		room = newRoomTemplate;
		room.roomId = roomId
		rooms[roomId] = room;
	}
	return room
}
function getSession(sessionID) {
	var session = null;
	if (sessions[sessionID]) {
		session = sessions[sessionID];
	} else {
		// Objects Templates
		var newSessionTemplate = { id: 0, janusServer: janusServer, room: 0, subscribers: [], publishers: [], isConnected: false };
		// new session template
		session = newSessionTemplate;
		session.id = sessionID;
		sessions[sessionID] = session;
		console.log("New session was burn !!!! ", sessionID, session)
	}
	return session
}
function setSession(session) {
	sessions[session.id] = session;
	console.log("session was update  !!!! ", session.id, session)
}
function setRoom(room) {
	rooms[room.roomId] = room;
}

module.exports = {
  sessions,
  tasks,
  publishers,
  rooms,
  managerSessions,
  getRoom,
  getSession,
  setSession,
  setRoom
}