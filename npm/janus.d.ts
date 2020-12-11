declare namespace JanusJS {
	interface Dependencies {
		adapter: any;
		WebSocket: (server: string, protocol: string) => WebSocket;
		isArray: (array: any) => array is Array<any>;
		extension: () => boolean;
		httpAPICall: (url: string, options: any) => void;
    }
    
    interface DependenciesResult {
		adapter: any;
		newWebSocket: (server: string, protocol: string) => WebSocket;
		isArray: (array: any) => array is Array<any>;
		extension: () => boolean;
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
		error?: Error;
	}

	interface PluginOptions {
		plugin: string;
		opaqueId?: string;
		success?: (handle: PluginHandle) => void;
		error?: (error: any) => void;
		consentDialog?: (on: boolean) => void;
		webrtcState?: (isConnected: boolean) => void;
		iceState?: (state: 'connected' | 'failed') => void;
		mediaState?: (medium: 'audio' | 'video', receiving: boolean, mid?: number) => void;
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
		isVideoMuted(): boolean;
		muteVideo(): void;
		unmuteVideo(): void;
		getBitrate(): number;
		hangup(sendRequest?: boolean): void;
		detach(params: any): void;
	}

	class Janus {
		static useDefaultDependencies(deps: Partial<Dependencies>): DependenciesResult;
		static useOldDependencies(deps: Partial<Dependencies>): DependenciesResult;
		static init(options: InitOptions): void;
		static isWebrtcSupported(): boolean;
		static debug(...args: any[]): void;
		static log(...args: any[]): void;
		static warn(...args: any[]): void;
		static error(...args: any[]): void;
		static randomString(length: number): string;
		static attachMediaStream(element: HTMLMediaElement, stream: MediaStream): void;
		static reattachMediaStream(to: HTMLMediaElement, from: HTMLMediaElement): void;

		constructor(options: ConstructorOptions);

		getServer(): string;
		isConnected(): boolean;
		getSessionId(): string;
		attach(options: PluginOptions): void;
		destroy(): void;
	}
}

export default JanusJS.Janus;
export { JanusJS };
