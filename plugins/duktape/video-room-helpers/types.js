/**
 * @typedef {{
 *  http_get: (url:string) => string;
 *  http_post: (url: string, body: string) => string;
 *  pushEvent: (id: number, tr: string, event: string, jsep: string | null);
 *  getModulesFolder: () => string;
 *  readFile: (path: string) => string | undefined;
 *  notifyEvent: (eventType: number, eventBodyJSON: string) => void;
 *  configureMedium: (id: number, mediaType: string, direction: string, bool: boolean) => void;
 *  addRecipient: (publisherSessionID: number, subscriberSessionID: number) => void;
 *  sendPli: (publisherSessionID: number) => void;
 *  pokeScheduler: () => void;
 *  removeRecipient: (publisherID: number, subscriberID: number) => void;
 *  relayTextData: (sessionID: number, data: string, lenght: number) => void;
 *  relayBinaryData: (sessionID: number, buffer: string, lenght: number) => void;
 *  setBitrate: (sessionID: number, bitrate: number) => void;
 *  stopRecording: (sessionID: number, audio: "audio" | null, video: "video" | null, data: "data" | null) => void;
 *  startRecording: (
 *    sessionID: number,
 *    audio: "audio" | null,
 *    audioCodec: string,
 *    audioFolderPath: string,
 *    audioFilePath: string,
 *    video: "video" | null,
 *    videoCodec: string,
 *    videoFolderPath: string,
 *    videoFilePath: string,
 *    data: "data" | null,
 *    dataText: string,
 *    dataFolderPath: string,
 *    dataFilePath: string
 * ) => void;
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
 janusServer: string;
 sessions: ISessions;
 tasks: ITasks;
 publishers?: number[];
 rooms: IRooms;
 managerSessions: IManagerSessions;
 getRoom: (roomID: number) => IRoom;
 getSession: (sessionID: number) => ISession;
 setSession: (session: ISession) => void;
 setRoom: (room: IRoom) => void;
}} IState
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
 *  display:string;
 *  janusServer: string;
 *  room: number;
 *  subscribers: Array<number>;
 *  publishers: Array<number>;
 *  isConnected: boolean;
 *  state: any;
 *  audioCodec?: string;
 *  videoCodec?: string;
 *  private_Id?: number
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

/**@typedef {{[room_id:number]: IRoom }} IRooms */

/**@typedef {{
 *  roomId: number;
 *  roomName: string;
 *  managerSessionID: number;
 *  publishers: Array<number>;
 *  sessions: Array<number>;
 * }} IRoom
 * */

/**
 * @typedef {{
 *  managerID: number;
 *  domain: string;
 * }} IManagerSession
 */

/**@typedef {{[id:number]: IManagerSession}} IManagerSessions */
