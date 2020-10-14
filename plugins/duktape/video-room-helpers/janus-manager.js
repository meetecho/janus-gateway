// @ts-check

/** 
 * janus manager helper functions
 * @param {IGlobal} global
 * @param {IState} state 
 * */
module.exports = function (global, state) {

  var util = require("./util")(global);

  /**
   * On State creating new room or manager disconnecting
   * It will send initial http request
   * @param {number} roomId
   * @returns {1 | -1}
   * */
  function connectToManager(roomId) {
    try {
      util.startRoomHttpRequest({
        room_id: roomId,
        server: state.janusServer,
        publisher_list: state.getRoomPublishersArray(roomId)
      });
      return 1;
    } catch (err) {
      console.log(err.toString());
      return -1;
    }
  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {object} body
   * */
  function handleManagerMessage(id, tr, body) {
    console.log('requesttt',body.request)
    switch (body.request) {
      case "join":
        return handleJoinManager(id, tr, body);
      case "sync":
        return handleSyncManager(id, tr, body);
      default:
        console.log("|ERROR| " + "not supported event name!");
    }
    return 1;
  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {IJanusJoinEventBody} body
   * */
  function handleJoinManager(id, tr, body) {
    var session = state.getSession(id);
    session.type = "manager";
    state.setSession(session);
    var msg = {
      test: "manager join success"
    }
    state.tasks.push({ id, tr, msg });
    global.pokeScheduler();
    console.log("(" + id + ") joined as a manager");
    return 1;
  }

  /**
   * @param {number} id
   * @param {string} tr
   * @param {IJanusResyncEventBody} body
   * */
  function handleSyncManager(id, tr, body) {
    var room = state.getRoom(body.room);
    room.publishers.forEach(function (el) {
      state.tasks.push({ id: el, tr, msg: body });
      // global.pushEvent(el, null, JSON.stringify(body), null);
    });
    global.pokeScheduler();
    return 1;
  }

  /**
   * Should be called when session state was changed
   * Should add task that will be sent to session manager with info about the session that was changed
   * Steps:
   *    1. get session by sessionId
   *    2. get managerId of the room by that session
   *    3. build message with session info
   *    4. push the message to the state.tasks
   *    5. run pokeScheduler
   * @param {number} sessionId
   * @param {string} reason
   * @param {number} [reasonMember]
   * @returns {void}
   */
  function syncSessionToManager(sessionId, reason, reasonMember) {
    var session = state.getSession(sessionId);
    var room = state.getRoom(session.room);
    var managerSessionID = room.managerSessionID;

    /**@type {IJanusMessage} */
    var message = {
      videoroom: reason,
      event: reason,
      publishers: state.getRoomPublishersArray(room.roomId),
      publisher_id: reasonMember
    };

    /**@type {ITask} */
    var task = {
      id: managerSessionID,
      tr: null,
      msg: message,
      jsep: null,
      jsepOffer: null
    };

    state.tasks.push(task);
    global.pokeScheduler();
  }

  return {
    connectToManager,
    handleManagerMessage,
    handleJoinManager,
    handleSyncManager,
    syncSessionToManager
  }
}