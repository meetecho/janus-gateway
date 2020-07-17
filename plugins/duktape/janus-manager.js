/**
 * @param {{room_id: number, server: string, publisher_list: any[]}} roomInfo
 * */
function connectToManager (roomInfo) {

};

/**
 * @param {number} id
 * @param {string} tr
 * @param {string} msg
 * */
function handleManagerMessage (id, tr, msg) {

};

/**
 * @param {number} id
 * @param {string} tr
 * @param {string} msg
 * */
function handleJoinManager (id, tr, msg) {

};

/**
 * @param {number} id
 * @param {string} tr
 * @param {string} msg
 * */
function handleSyncManager(id, tr, msg) {

};

/**
 * @param {{room_id: number, server: string, publisher_list: any[]}} roomInfo
 * */
function syncRoomToManager (roomInfo) {

};

module.exports = {
	connectToManager,
	handleManagerMessage,
	handleJoinManager,
	handleSyncManager,
	syncRoomToManager
};
