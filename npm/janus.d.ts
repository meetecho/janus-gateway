declare namespace JanusJS {
	interface Dependencies {
		adapter: any;
		newWebSocket: (server: string, protocol: string) => WebSocket;
		isArray: (array: any) => array is Array<any>;
		checkJanusExtension: () => boolean;
		httpAPICall: (url: string, options: any) => void;
	}

	enum DebugLevel {
		Trace = 'trace',
		Debug = 'debug',
		Log = 'log',
		Warning = 'warn',
		Error = 'error'
	}

	interface JSEP {}

	interface InitOptions {
		debug?: boolean | 'all' | DebugLevel[];
		callback?: Function;
		dependencies?: Dependencies;
	}

	interface ConstuctorOptions {
		server: string | string[];
		iceServers?: string[];
		ipv6?: boolean;
		withCredentials?: boolean;
		max_poll_events?: number;
		destroyOnUnload?: boolean;
		token?: string;
		apisecret?: string;
		success?: Function;
		error?: (error: any) => void;
		destroyed?: Function;
	}

	enum MessageType {
		Recording = 'recording',
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
	}

	interface PluginOptions {
		plugin: string;
		opaqueId?: string;
		success?: (handle: PluginHandle) => void;
		error?: (error: any) => void;
		consentDialog?: (on: boolean) => void;
		webrtcState?: (isConnected: boolean) => void;
		iceState?: (state: 'connected' | 'failed') => void;
		mediaState?: (state: { type: 'audio' | 'video'; on: boolean }) => void;
		slowLink?: (state: { uplink: boolean }) => void;
		onmessage?: (message: Message, jsep?: JSEP) => void;
		onlocalstream?: (stream: MediaStream) => void;
		onremotestream?: (stream: MediaStream) => void;
		ondataopen?: Function;
		ondata?: Function;
		oncleanup?: Function;
		detached?: Function;
	}

	interface OfferParams {
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
		trickle?: boolean;
		stream?: MediaStream;
		success: Function;
		error: (error: any) => void;
	}

	interface PluginMessage {
		message: {
			request: string;
			[otherProps: string]: any;
		};
		jsep?: JSEP;
	}

	interface PluginHandle {
		getId(): string;
		getPlugin(): string;
		send(message: PluginMessage): void;
		createOffer(params: any): void;
		createAnswer(params: any): void;
		handleRemoteJsep(params: { jsep: JSEP }): void;
		dtmf(params: any): void;
		data(params: any): void;
		getBitrate(): number;
		hangup(sendRequest?: boolean): void;
		detach(params: any): void;
	}

	class Janus {
		static useDefaultDependencies(deps: Partial<Dependencies>): Dependencies;
		static useOldDependencies(deps: Partial<Dependencies>): Dependencies;
		static init(options: InitOptions): void;
		static isWebrtcSupported(): boolean;
		static debug(...args: any[]): void;
		static log(...args: any[]): void;
		static warn(...args: any[]): void;
		static error(...args: any[]): void;
		static randomString(length: number): string;

		constructor(options: ConstuctorOptions);

		getServer(): string;
		isConnected(): boolean;
		getSessionId(): string;
		attach(options: PluginOptions): void;
		destroy(): void;
	}
}

export default JanusJS.Janus;
export { JanusJS };
