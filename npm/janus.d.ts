declare global {
	const jQuery: any
}

declare namespace JanusJS {
	interface Dependencies {
		adapter: any;
		WebSocket: (server: string, protocol: string) => WebSocket;
		isArray: (array: any) => array is Array<any>;
		extension: ChromeExtension;
		httpAPICall: (url: string, options: HttpApiCallOption) => void;
	}

	interface DefaultDependencies extends Dependencies {
		fetch: typeof fetch;
		Promise: PromiseConstructorLike;
	}

	interface OldDependencies extends Dependencies {
		jQuery: typeof jQuery;
	}

	interface DependenciesResult {
		adapter: any;
		newWebSocket: (server: string, protocol: string) => WebSocket;
		isArray: (array: any) => array is Array<any>;
		extension: ChromeExtension;
		httpAPICall: (url: string, options: HttpApiCallOption) => void;
	}

	type ChromeExtension = {
		cache?: { [key in string]: GetScreenCallback },
		extensionId: string;
		isInstalled: () => boolean;
		getScreen: (callback: GetScreenCallback) => void;
		init: () => void;
	}

	type GetScreenCallback = (error:string, sourceId:string) => void

	type HttpApiCallOption = {
		async: boolean,
		verb: string,
		body: JanusRequest,
		timeout: number,
		withCredentials: boolean,
		success: (result: unknown) => void,
		error: (error: string, reason?: unknown) => void,
	}

	type JanusRequest = {
		plugin?: string,
		token?: string,
		apisecret?: string,
		session_id?: number,
		handle_id?: number,
		opaque_id?: string,
		loop_index?: number,
		janus: string,
		transaction: string,
		body?: any,
		jsep?: JSEP,
	}

	enum DebugLevel {
		Trace = 'trace',
		vDebug = 'vdebug',
		Debug = 'debug',
		Log = 'log',
		Warning = 'warn',
		Error = 'error',
	}

	interface JSEP {
		e2ee?: boolean;
		sdp?: string;
		type?: string;
		rid_order?: "hml" | "lmh";
		force_relay?: boolean;
	}

	interface InitOptions {
		debug?: boolean | 'all' | DebugLevel[];
		callback?: Function;
		dependencies?: DependenciesResult;
	}

	interface ConstructorOptions {
		server: string | string[];
		iceServers?: RTCIceServer[];
		ipv6?: boolean;
		withCredentials?: boolean;
		max_poll_events?: number;
		destroyOnUnload?: boolean;
		token?: string;
		apisecret?: string;
		success?: Function;
		error?: (error: any) => void;
		destroyed?: Function;
		iceTransportPolicy?: RTCIceTransportPolicy;
		bundlePolicy?: RTCBundlePolicy;
		keepAlivePeriod?: number;
		longPollTimeout?: number;
	}

	interface ReconnectOptions {
		success?: Function;
		error?: (error: string) => void;
	}

	interface DestroyOptions {
		cleanupHandles?: boolean;
		notifyDestroyed?: boolean;
		unload?: boolean;
		success?: () => void;
		error?: (error: string) => void;
	}

	interface GetInfoOptions {
		success?: (info: any) => void;
		error?: (error: string) => void;
	}

	interface RemoteTrackMetadata {
		reason: "created" | "ended" | "mute" | "unmute";
	}

	enum MessageType {
		Recording = 'recording',
		Starting = 'starting',
		Started = 'started',
		Stopped = 'stopped',
		SlowLink = 'slow_link',
		Preparing = 'preparing',
		Refreshing = 'refreshing'
	}

	interface Message {
		result?: {
			status: MessageType;
			id?: string;
			uplink?: number;
		};
		error?: string;
		[key: string]: any;
	}

	interface PluginCallbacks {
		dataChannelOptions?: RTCDataChannelInit;
		success?: (handle: PluginHandle) => void;
		error?: (error: string) => void;
		consentDialog?: (on: boolean) => void;
		webrtcState?: (isConnected: boolean) => void;
		iceState?: (state: 'connected' | 'failed' | 'disconnected' | 'closed') => void;
		mediaState?: (medium: 'audio' | 'video', receiving: boolean, mid?: number) => void;
		slowLink?: (uplink: boolean, lost: number, mid: string) => void;
		onmessage?: (message: Message, jsep?: JSEP) => void;
		onlocaltrack?: (track: MediaStreamTrack, on: boolean) => void;
		onremotetrack?: (track: MediaStreamTrack, mid: string, on: boolean, metadata?: RemoteTrackMetadata) => void;
		ondataopen?: Function;
		ondata?: Function;
		oncleanup?: Function;
		ondetached?: Function;
	}

	interface PluginOptions extends PluginCallbacks {
		plugin: string;
		opaqueId?: string;
		token?: string;
		loopIndex?: number;
	}

	interface OfferParams {
		tracks?: TrackOption[];
		trickle?: boolean;
		iceRestart?: boolean;
		externalEncryption?: boolean;
		success?: (jsep: JSEP) => void;
		error?: (error: Error) => void;
		customizeSdp?: (jsep: JSEP) => void;

		/** @deprecated use tracks instead */
		media?: {
			audioSend?: boolean;
			audioRecv?: boolean;
			videoSend?: boolean;
			videoRecv?: boolean;
			audio?: boolean | { deviceId: string };
			video?:
				| boolean
				| { deviceId: string }
				| 'lowres'
				| 'lowres-16:9'
				| 'stdres'
				| 'stdres-16:9'
				| 'hires'
				| 'hires-16:9';
			data?: boolean;
			failIfNoAudio?: boolean;
			failIfNoVideo?: boolean;
			screenshareFrameRate?: number;
		};
	}

	interface PluginMessage {
		message: {
			request: string;
			[otherProps: string]: any;
		};
		jsep?: JSEP;
		success?: (data?: any) => void;
		error?: (error: string) => void;
	}

	interface WebRTCInfo {
		bitrate: {
			bsbefore: string | null;
			bsnow: string | null;
			timer: string | null;
			tsbefore: string | null;
			tsnow: string | null;
			value: string | null;
		};
		dataChannel: { [key in string]: RTCDataChannel };
		dataChannelOptions: RTCDataChannelInit;

		dtmfSender: RTCDTMFSender
		iceDone: boolean;
		mediaConstraints: any;
		mySdp: {
			sdp: string;
			type: string;
		};
		myStream: MediaStream;
		pc: RTCPeerConnection;
		receiverTransforms: {
			audio: TransformStream;
			video: TransformStream;
		};
		remoteSdp: string;
		remoteStream: MediaStream;
		senderTransforms: {
			audio: TransformStream;
			video: TransformStream;
		};
		started: boolean;
		streamExternal: boolean;
		trickle: boolean;
		volume: {
			value: number;
			timer: number;
		};

		sdpSent: boolean;
		insertableStreams?: boolean;
		externalEncryption?: boolean;
		candidates: RTCIceCandidateInit[];
	}

	type PluginCreateAnswerParam = {
		jsep: JSEP;
		tracks?: TrackOption[];
		externalEncryption?: boolean;

		/** @deprecated use tracks instead */
		media?: { audioSend: any, videoSend: any };
		success?: (data: JSEP) => void;
		error?: (error: string) => void;
	}

	type PluginHandleRemoteJsepParam = {
		jsep: JSEP;
		success?: (data: JSEP) => void;
		error?: (error: string) => void;
	}

	type PluginReplaceTracksParam = {
		tracks: TrackOption[];
		success?: (data: unknown) => void;
		error?: (error: string) => void;
	}

	type TrackOption = {
		add?: boolean;
		replace?: boolean;
		remove?: boolean;
		type: 'video' | 'screen' | 'audio' | 'data';
		mid?: string;
		capture: boolean | MediaTrackConstraints | MediaStreamTrack;
		recv?: boolean;
		group?: 'default' | string;
		gumGroup?: TrackOption['group'];
		simulcast?: boolean;
		svc?: string;
		simulcastMaxBitrates?: {
			low: number;
			medium: number;
			high: number;
		};
		sendEncodings?: RTCRtpEncodingParameters[];
		framerate?: number;
		bitrate?: number;
		dontStop?: boolean;
		transforms?: {
			sender: ReadableWritablePair;
			receiver: ReadableWritablePair;
		};
	}

	type PluginDtmfParam = {
		dtmf: Dtmf;
		success?: (data: unknown) => void;
		error?: (error: string) => void;
	}

	type Dtmf = {
		tones: string;
		duration: number;
		gap: number;
	}

	type PluginDataParam = {
		/** @deprecated use data instead */
		text?: string;
		data?: any;
		label?: string;
		protocol?: string;
		success?: (data: unknown) => void;
		error?: (error: string) => void;
	}

	type TrackDesc = {
		mid?: string
		type?: string
		id?: string
		label?: string
	}

	interface DetachOptions {
		success?: () => void;
		error?: (error: string) => void;
		noRequest?: boolean;
	}

	interface PluginHandle {
		plugin: string;
		id: string;
		token?: string;
		detached: boolean;
		webrtcStuff: WebRTCInfo;
		getId(): string;
		getPlugin(): string;
		getVolume(mid: string, callback: (result: number) => void): void;
		getRemoteVolume(mid: string, callback: (result: number) => void): void;
		getLocalVolume(mid: string, callback: (result: number) => void): void;
		isAudioMuted(): boolean;
		muteAudio(): void;
		unmuteAudio(): void;
		isVideoMuted(): boolean;
		muteVideo(): void;
		unmuteVideo(): void;
		getBitrate(mid? :string): string;
		setMaxBitrate(bitrate: number): void;
		send(message: PluginMessage): void;
		data(params: PluginDataParam): void;
		dtmf(params: PluginDtmfParam): void;
		createOffer(params: OfferParams): void;
		createAnswer(params: PluginCreateAnswerParam): void;
		handleRemoteJsep(params: PluginHandleRemoteJsepParam): void;
		replaceTracks(params: PluginReplaceTracksParam): void;
		getLocalTracks(): TrackDesc[];
		getRemoteTracks(): TrackDesc[];
		hangup(sendRequest?: boolean): void;
		detach(params?: DetachOptions): void;
	}

	class Janus {
		static webRTCAdapter: any;
		static safariVp8: boolean;
		static useDefaultDependencies(deps?: Partial<DefaultDependencies>): DependenciesResult;
		static useOldDependencies(deps?: Partial<OldDependencies>): DependenciesResult;
		static init(options: InitOptions): void;
		static isWebrtcSupported(): boolean;
		static debug(...args: any[]): void;
		static log(...args: any[]): void;
		static warn(...args: any[]): void;
		static error(...args: any[]): void;
		static randomString(length: number): string;
		static attachMediaStream(element: HTMLMediaElement, stream: MediaStream): void;
		static reattachMediaStream(to: HTMLMediaElement, from: HTMLMediaElement): void;

		static stopAllTracks(stream: MediaStream): void;

		constructor(options: ConstructorOptions);

		attach(options: PluginOptions): void;
		getServer(): string;
		isConnected(): boolean;
		reconnect(callbacks: ReconnectOptions): void;
		getSessionId(): number;
		getInfo(callbacks: GetInfoOptions): void;
		destroy(callbacks: DestroyOptions): void;
	}
}

export default JanusJS.Janus;
export { JanusJS };
