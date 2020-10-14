/**
 * @typedef {{
 *  http_get: (url:string) => string;
 *  http_post: (url: string, body: string) => string;
 *  pushEvent: (id: number, tr: string, event: string, jsep: string | null);
 *  getModulesFolder: () => string;
 *  readFile: (path: string) => string | undefined;
 *  notifyEvent: (eventType: number, eventBodyJSON: string) => void;
 *  configureMedium: (id: number, mediaType: string, direction: string, bool: boolean) => void;
 *  querySession: (id:number) => json
 *  addRecipient: (publisherSessionID: number, subscriberSessionID: number) => void;
 *  sendPli: (publisherSessionID: number) => void;
 *  pokeScheduler: () => void;
 *  removeRecipient: (publisherID: number, subscriberID: number) => void;
 *  relayTextData: (sessionID: number, data: string, lenght: number) => void;
 *  relayBinaryData: (sessionID: number, buffer: string, lenght: number) => void;
 *  setBitrate: (sessionID: number, bitrate: number) => void;
 *  stopRecording: (sessionID: number, audio: "audio" | null, video: "video" | null, data: "data" | null) => void;
 *  jwt_validate: (jwt: string, secret: string) => object;
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

/**@typedef {{
 *  id: number;
 *  display:string;
 *  room: number;
 *  janusServer: string;
 *  subscribers: Array<number>;
 *  publishers: Array<number>;
 *  isConnected: boolean;
 *  audioCodec?: string;
 *  videoCodec?: string;
 *  private_Id?: number;
 *  type?: "publisher" | "subscriber" | "manager";
 *  state?: any;
 * }} ISession
 * */

/** @typedef {{
 * room_id: number;
 * server: string;
 * publisher_list: Array<ISession>
 * }} IRoomInfo */

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
 newSession: (sessionID: number) => ISession;
 deleteSession: (sessionID: number) => void
 deleteRoom: (roomID: number) => void
 setRoom: (room: IRoom) => void;
 newRoom: (roomID: number) => IRoom;
 getRoomPublishers: (roomId: number, filterPublisher: number) => ISessions;
 getRoomPublishersArray: (roomId: number, filterPublisher? : number) => Array<ISession>;
}} IState
*/

/**
 * @typedef {{
  meetingID: number;
  sessionID: number;
  handleID: number;
  request: string;
  ptype: string;
}} IBody
*/

/**
 * @typedef {{[id: number]: ISession}} ISessions
 */

/**@typedef {{
 *  id: number;
 *  tr?: string;
 *  msg: {[key:string]: any};
 *  jsep?: IJSEP;
 *  jsepOffer?: IJSDP;
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
 *  managerID?: number;
 *  domain: string;
 * }} IManagerSession
 */

/**@typedef {{[id:number]: IManagerSession}} IManagerSessions */

/**@typedef {{
 *  sdp: string;
 *  type: "answer" | "offer";
 *  value?: string;
 * }} IJSEP */

/**@typedef {Array<{
* 	type: string;
* 	name: string;
* 	value?: string;
* }>} IJSDP
* */

/**@typedef {{
 *  videoroom: string;
 *  event: string;
 *  publishers: Array<ISession>;
 *  newPublisher?: number;
 *  publisher_id?: number;
 * }} IJanusMessage
 */

/**@typedef {{
 *   request: string;
 *   reason: string;
 *   reason_member: number | null;
 *   ptype: "manager";
 *   room: number;
 *   members: IMembers;
 *   disconnected_members: IMembers;
 * }} IJanusResyncEventBody
 *  */

/**@typedef {{
 *   request: string;
 *   room: number;
 *   ptype: "publisher" | "subscriber" | "manager";
 *   display?: string;
 *   opaque_id?: string;
 *   server?: string;
 * }} IJanusJoinEventBody
 *  */

/**@typedef {{[memberID: number]: IMember}} IMembers */

/**@typedef {{
 *    MemberID: number;
 *    MeetingID: number;
 *    Data: {[key:string]: any};
 *    State: {[key:string: any]};
 *    AudioState: {[key: string]: IAudioStateItem};
 *    VideoState: {[key: string]: IVideoStateItem};
 * }} IMember */

/**@typedef {{
 *   "Hear": boolean;
 *   "Speak": boolean;
 *   "Talking": boolean;
 *   "Mute-Detect": boolean;
 *   "Current-Energy": number;
 * }} IAudioStateItem
 * */

/**@typedef {{
 * domain: string;
 * session_id: number;
 * created?: string;
 * updated?: string;
 * codecs?: { videoCodec?: string; };
 * data?: ISession;
}} IVideoStateItem
*/