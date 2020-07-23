/**
 * @typedef {{
 *  http_get: (url:string) => string;
 *  http_post: (url: string, body: string) => string;
 *  pushEvent: (id: number, tr: string, event: string, jsep: string | null)
 * }} IGlobal
 */

/**
 * @typedef {{
  *  audioCodec: string;
  *  display: string;
  *  id: number;
  *  isConnected: boolean;
  *  janusServer: string;
  *  private_Id: number;
  *  publishers: Array<number>;
  *  room: number;
  *  subscribers: Array<number>;
  *  videoCodec: string;
  * }} IPublisherStateItem
  */

/**
 * @typedef {{
 *  room_id: number;
 *  server: string;
 *  publisher_state: Array<IPublisherStateItem>;
 * }} IJanusHTTPBody
 */


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

/** @typedef {{room_id: number, server: string, publisher_list: Array<IPublisherStateItem>}} IRoomInfo */

/**
 * @typedef {{
  meetingID: number;
  sessionID: number;
  handleID: number;
  request: string;
  ptype: string;
}} IBody
*/

/**@typedef {{
 *  id: number;
 *  janusServer: string;
 *  room: number;
 *  subscribers: Array<number>;
 *  publishers: Array<number>;
 *  isConnected: boolean;
 * }} ISession */

/**
 * @typedef {{[id: number]: ISession}} ISessions
 */

/**@typedef {{
 *  id: number;
 *  tr: string;
 *  msg: object;
 *  jsep: object;
 * }} ITask
 * */

/**@typedef {Array<ITask>} ITasks */

/**@typedef {{
 *  
 * }} IRoom */

/**@typedef {[room_id:number]: IRoom } IRooms */