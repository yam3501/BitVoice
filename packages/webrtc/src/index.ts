import type { TurnCredentialProvider } from './turn.js';

export const packageName = '@securevoice/webrtc';
export type CallState =
	| 'idle'
	| 'outgoing-preparing'
	| 'outgoing-rendezvous'
	| 'outgoing-connecting'
	| 'ice-connected'
	| 'incoming-offer'
	| 'incoming-review'
	| 'incoming-accepted'
	| 'incoming-connecting'
	| 'connected'
	| 'ending'
	| 'ended';

export type CallEvent =
	| 'prepare-outgoing'
	| 'offer-sent'
	| 'offer-accepted'
	| 'incoming-received'
	| 'review-incoming'
	| 'accept-incoming'
	| 'connection-established'
	| 'finish-confirmed'
	| 'connection-failed'
	| 'end'
	| 'cleanup';

const MAX_PENDING_ICE_CANDIDATES = 64;

const transitions: Record<CallState, Partial<Record<CallEvent, CallState>>> = {
	idle: { 'prepare-outgoing': 'outgoing-preparing', 'incoming-received': 'incoming-offer' },
	'outgoing-preparing': { 'offer-sent': 'outgoing-rendezvous', end: 'ending' },
	'outgoing-rendezvous': { 'offer-accepted': 'outgoing-connecting', 'incoming-received': 'incoming-offer', end: 'ending' },
	'outgoing-connecting': { 'connection-established': 'ice-connected', 'connection-failed': 'ending', end: 'ending' },
	'incoming-offer': { 'review-incoming': 'incoming-review', end: 'ending' },
	'incoming-review': { 'accept-incoming': 'incoming-accepted', end: 'ending' },
	'incoming-accepted': { 'offer-sent': 'incoming-connecting', end: 'ending' },
	'incoming-connecting': { 'connection-established': 'ice-connected', 'connection-failed': 'ending', end: 'ending' },
	'ice-connected': { 'finish-confirmed': 'connected', 'connection-failed': 'ending', end: 'ending' },
	connected: { end: 'ending' },
	ending: { cleanup: 'ended' },
	ended: {},
};

export function transitionCall(state: CallState, event: CallEvent): CallState {
	const next = transitions[state][event];
	if (!next) throw new Error(`illegal call transition: ${state} -> ${event}`);
	return next;
}

export type PrivacyMode = 'direct-preferred' | 'private-relay-only';

export type SignalPayload = {
	signal: RTCSessionDescriptionInit | RTCIceCandidateInit;
	privacyMode?: PrivacyMode;
};

export type CallFinishChallenge = {
	type: 'CALL_FINISH_CHALLENGE';
	challenge: string;
};

export type CallFinish = {
	type: 'CALL_FINISH';
	signature: string;
};

export type MediaPreferences = {
	audio: boolean;
	video: boolean;
};

export type DirectCallConfig = {
	localKeyId: string;
	remoteKeyId: string;
	turnProvider?: TurnCredentialProvider;
	stunServers?: string[];
	privacyMode?: PrivacyMode;
	mediaPreferences?: MediaPreferences; // If undefined, defaults to audio-only for backwards compatibility
	onSignal: (payload: SignalPayload) => Promise<void>;
	onStateChange?: (state: CallState) => void;
	onTrace?: (msg: string) => void;
	onLocalStream?: (stream: MediaStream) => void;
	onRemoteStream?: (stream: MediaStream) => void;
	createChallenge?: () => Promise<CallFinishChallenge>;
	createFinish?: (challenge: CallFinishChallenge) => Promise<CallFinish>;
	verifyFinish?: (finish: CallFinish, expectedChallenge: CallFinishChallenge) => Promise<boolean>;
};

export type DirectCall = {
	get state(): CallState;
	get peerConnection(): RTCPeerConnection | undefined;
	get pendingOffer(): RTCSessionDescriptionInit | undefined;
	startOutgoing(): Promise<RTCSessionDescriptionInit>;
	receiveOffer(payload: SignalPayload): Promise<void>;
	acceptIncoming(): Promise<RTCSessionDescriptionInit>;
	receiveAnswer(payload: SignalPayload): Promise<void>;
	receiveIceCandidate(payload: SignalPayload): Promise<void>;
	restartIce(): Promise<void>;
	end(): Promise<void>;
	toggleAudio(enabled: boolean): void;
	toggleVideo(enabled: boolean): void;
};

export function createDirectCall(config: DirectCallConfig): DirectCall {
	let state: CallState = 'idle';
	let connection: RTCPeerConnection | undefined;
	let localStream: MediaStream | undefined;
	let pendingOffer: RTCSessionDescriptionInit | undefined;
	let pendingCandidates: RTCIceCandidateInit[] = [];
	let controlChannel: RTCDataChannel | undefined;
	let localChallenge: CallFinishChallenge | undefined;
	let challengeRequested = false;
	let finishSent = false;
	let finishTimeout: ReturnType<typeof setTimeout> | undefined;
	let iceRestartUsed = false;
	let resolvedIceServers: RTCIceServer[] = [];

	const prepareIceServers = async () => {
		if (config.turnProvider) {
			try {
				resolvedIceServers = await config.turnProvider();
			} catch {
				if (config.privacyMode === 'private-relay-only') {
					throw new Error('Failed to obtain TURN credentials for private-relay-only mode');
				}
				resolvedIceServers = [];
			}
		} else if (config.privacyMode === 'private-relay-only') {
			throw new Error('private-relay-only mode requires a turnProvider');
		}

		if (config.privacyMode !== 'private-relay-only' && config.stunServers && config.stunServers.length > 0) {
			resolvedIceServers.push({ urls: config.stunServers });
		}
	};

	const setState = (next: CallState) => { state = next; config.onStateChange?.(next); };
	const trace = (msg: string) => config.onTrace?.(msg);
	const move = (event: CallEvent) => setState(transitionCall(state, event));
	let statsInterval: ReturnType<typeof setInterval> | undefined;
	const startStatsPolling = () => {
		if (statsInterval) return;
		statsInterval = setInterval(async () => {
			if (!connection || state !== 'connected') return;
			try {
				const stats = await connection.getStats();
				let selectedPair: Record<string, unknown> | undefined = undefined;
				stats.forEach(report => {
					const r = report as Record<string, unknown>;
					if (r.type === 'candidate-pair' && r.nominated && r.state === 'succeeded') {
						selectedPair = r;
					}
				});
				if (selectedPair) {
					const p = selectedPair as Record<string, unknown>;
					const local = stats.get(p.localCandidateId as string);
					const remote = stats.get(p.remoteCandidateId as string);
					if (local && remote) {
						const isRelay = local.candidateType === 'relay' || remote.candidateType === 'relay';
						trace(`Selected candidate pair:
  local: ${local.candidateType}
  remote: ${remote.candidateType}
  path: ${isRelay ? 'relay' : 'direct'}`);
					}
					// Only log once we find it
					if (statsInterval) clearInterval(statsInterval);
					statsInterval = undefined;
				}
			} catch {
				// ignore stats error
			}
		}, 2000);
	};

	const ensureConnection = () => {
		if (connection) return connection;
		connection = new RTCPeerConnection({
			iceServers: resolvedIceServers,
			iceTransportPolicy: config.privacyMode === 'private-relay-only' ? 'relay' : 'all',
			bundlePolicy: 'max-bundle',
			rtcpMuxPolicy: 'require',
		});
		connection.onicecandidate = (event) => {
			if (event.candidate === null) return;
			if (event.candidate) {
				const type = event.candidate.type;
				trace(`ICE gathering: ${type}`);
				void config.onSignal({ signal: event.candidate.toJSON(), privacyMode: config.privacyMode });
			}
		};
		connection.onicecandidateerror = (event: Event | RTCPeerConnectionIceErrorEvent) => {
			const errEvent = event as RTCPeerConnectionIceErrorEvent;
			trace(`ICE candidate error: code=${errEvent.errorCode} text=${errEvent.errorText} url=${errEvent.url}`);
		};
		connection.onsignalingstatechange = () => {
			trace(`Signaling state changed to: ${connection?.signalingState}`);
		};
		connection.onicegatheringstatechange = () => {
			trace(`ICE gathering state changed to: ${connection?.iceGatheringState}`);
		};
		connection.oniceconnectionstatechange = () => {
			const iceState = connection?.iceConnectionState;
			trace(`ICE connection state changed to: ${iceState}`);
			if (iceState === 'checking' || iceState === 'connected' || iceState === 'completed' || iceState === 'failed' || iceState === 'disconnected' || iceState === 'closed') {
				trace(`ICE reached state: ${iceState}`);
			}
			if (iceState === 'failed' && connection) {
				void connection.getStats().then(stats => {
					let selectedPair: Record<string, unknown> | undefined = undefined;
					stats.forEach(report => {
						const r = report as Record<string, unknown>;
						if (r.type === 'candidate-pair' && (r.nominated || r.state === 'failed' || r.state === 'in-progress')) {
							if (!selectedPair || r.nominated) {
								selectedPair = r;
							}
						}
					});
					if (selectedPair) {
						const p = selectedPair as Record<string, unknown>;
						const local = stats.get(p.localCandidateId as string);
						const remote = stats.get(p.remoteCandidateId as string);
						trace(`ICE Failure metadata:
  pair state: ${p.state}
  nominated: ${p.nominated}
  local: ${local?.candidateType}
  remote: ${remote?.candidateType}
  protocol: ${local?.protocol}`);
					} else {
						trace('ICE Failure metadata: No candidate pair found');
					}
				}).catch(() => {});
			}
		};
		connection.onconnectionstatechange = () => {
			trace(`Connection state changed to: ${connection?.connectionState}`);
			if (connection?.connectionState === 'connected') {
				if (state === 'outgoing-connecting' || state === 'incoming-connecting') {
					move('connection-established');
					if (!config.createChallenge) {
						move('finish-confirmed');
					} else {
						if (!finishTimeout) {
							finishTimeout = setTimeout(() => {
								if (state === 'ice-connected') {
									move('connection-failed');
								}
							}, 10000);
						}
						void sendChallenge();
					}
				}
				if (state === 'connected') {
					startStatsPolling();
				}
			} else if (connection && ['failed', 'disconnected'].includes(connection.connectionState) && state === 'outgoing-connecting') {
				move('connection-failed');
			}
		};
		connection.ondatachannel = (event) => { controlChannel = event.channel; configureControlChannel(controlChannel); };
		connection.ontrack = (event) => { if (event.streams[0]) config.onRemoteStream?.(event.streams[0]); };
		return connection;
	};
	const sendChallenge = async () => {
		if (challengeRequested || localChallenge || !controlChannel || controlChannel.readyState !== 'open' || state !== 'ice-connected' || !config.createChallenge) return;
		challengeRequested = true;
		
		localChallenge = await config.createChallenge();
		controlChannel.send(JSON.stringify(localChallenge));
	};
	const configureControlChannel = (channel: RTCDataChannel) => {
		channel.onopen = () => { void sendChallenge(); };
		channel.onmessage = (event) => {
			if (state !== 'ice-connected' || typeof event.data !== 'string') return;
			try {
				const msg = JSON.parse(event.data);
				if (msg.type === 'CALL_FINISH_CHALLENGE' && config.createFinish) {
					if (!finishSent) {
						finishSent = true;
						void config.createFinish(msg as CallFinishChallenge).then((finish) => {
							if (controlChannel?.readyState === 'open') {
								controlChannel.send(JSON.stringify(finish));
							}
						});
					}
				} else if (msg.type === 'CALL_FINISH' && config.verifyFinish && localChallenge) {
					void config.verifyFinish(msg as CallFinish, localChallenge).then((valid) => { 
						if (valid && state === 'ice-connected') {
							if (finishTimeout) clearTimeout(finishTimeout);
							move('finish-confirmed'); 
						} 
					});
				}
			} catch {
				// ignore invalid JSON
			}
		};
	};
	const requestMedia = async () => {
		const preferences = config.mediaPreferences ?? { audio: true, video: false };
		localStream = await navigator.mediaDevices.getUserMedia(preferences);
		config.onLocalStream?.(localStream);
		for (const track of localStream.getTracks()) ensureConnection().addTrack(track, localStream);
	};

	return {
		get state() { return state; },
		get peerConnection() { return connection; },
		get pendingOffer() { return pendingOffer ? { ...pendingOffer } : undefined; },
		async startOutgoing() {
			move('prepare-outgoing');
			await prepareIceServers();
			await requestMedia();
			const peer = ensureConnection();
			controlChannel = peer.createDataChannel('securevoice-control', { ordered: true });
			configureControlChannel(controlChannel);
			const offer = await peer.createOffer();
			await peer.setLocalDescription(offer);
			move('offer-sent');
			await config.onSignal({ signal: offer, privacyMode: config.privacyMode });
			return offer;
		},
		async receiveOffer(payload) {
			if (payload.privacyMode === 'private-relay-only' && config.privacyMode !== 'private-relay-only') {
				throw new Error('Peer requested private-relay-only mode, but local config is direct-preferred');
			}
			if (config.privacyMode === 'private-relay-only' && payload.privacyMode !== 'private-relay-only') {
				throw new Error('Local requires private-relay-only mode, but peer requested direct-preferred');
			}
			if (state === 'outgoing-rendezvous') {
				const polite = config.localKeyId < config.remoteKeyId;
				if (!polite) {
					return;
				}
				if (connection) {
					connection.close();
					connection = undefined;
					controlChannel = undefined;
				}
				if (localStream) {
					for (const track of localStream.getTracks()) track.stop();
					localStream = undefined;
				}
				iceRestartUsed = false;
				challengeRequested = false;
				finishSent = false;
				localChallenge = undefined;
				if (finishTimeout) clearTimeout(finishTimeout);
				finishTimeout = undefined;
				if (statsInterval) clearInterval(statsInterval);
				statsInterval = undefined;
				pendingCandidates = [];
			}
			move('incoming-received');
			pendingOffer = payload.signal as RTCSessionDescriptionInit;
			move('review-incoming');
		},
		async acceptIncoming() {
			if (!pendingOffer) throw new Error('no incoming offer to accept');
			const offer = pendingOffer;
			pendingOffer = undefined;
			move('accept-incoming');
			
			try {
				await prepareIceServers();
				await requestMedia(); // calls ensureConnection() which creates RTCPeerConnection, then getUserMedia()
				await ensureConnection().setRemoteDescription(offer);
				const answer = await ensureConnection().createAnswer();
				await ensureConnection().setLocalDescription(answer);
				
				await config.onSignal({ signal: answer, privacyMode: config.privacyMode });
				move('offer-sent'); // transitioning to incoming-connecting in the state machine
				
				for (const candidate of pendingCandidates) {
					await ensureConnection().addIceCandidate(candidate).then(() => {
						trace('addIceCandidate(buffered) succeeded');
					}).catch((err) => {
						trace(`addIceCandidate(buffered) failed: ${err.message}`);
					});
				}
				pendingCandidates = [];
				return answer;
			} catch (err) {
				if (connection) {
					connection.close();
					connection = undefined;
				}
				if (localStream) {
					localStream.getTracks().forEach((track) => track.stop());
					localStream = undefined;
				}
				pendingCandidates = [];
				if (state !== 'ending' && state !== 'ended') move('end');
				if (state === 'ending') move('cleanup');
				throw err;
			}
		},
		async receiveAnswer(payload) {
			if (payload.privacyMode === 'private-relay-only' && config.privacyMode !== 'private-relay-only') {
				throw new Error('Peer requested private-relay-only mode, but local config is direct-preferred');
			}
			if (config.privacyMode === 'private-relay-only' && payload.privacyMode !== 'private-relay-only') {
				throw new Error('Local requires private-relay-only mode, but peer requested direct-preferred');
			}
			move('offer-accepted');
			await ensureConnection().setRemoteDescription(payload.signal as RTCSessionDescriptionInit);
			for (const init of pendingCandidates) {
				await connection?.addIceCandidate(init).catch(e => trace(`buffered addIceCandidate failed: ${e.message}`));
			}
			pendingCandidates = [];
		},
		async receiveIceCandidate(payload) {
			if (state === 'ended' || state === 'ending') return;

			const init = payload.signal as RTCIceCandidateInit;
			if (init === null) return;
			
			if (typeof init.candidate !== 'string') throw new Error('Invalid ICE candidate payload');
			if (init.candidate.length > 2048) throw new Error('ICE candidate exceeds maximum allowed length');
			if (init.sdpMid !== undefined && init.sdpMid !== null && typeof init.sdpMid !== 'string') throw new Error('Invalid sdpMid');
			if (init.sdpMLineIndex !== undefined && init.sdpMLineIndex !== null && typeof init.sdpMLineIndex !== 'number') throw new Error('Invalid sdpMLineIndex');
			if (init.usernameFragment !== undefined && init.usernameFragment !== null && typeof init.usernameFragment !== 'string') throw new Error('Invalid usernameFragment');

			if (state === 'incoming-review' || state === 'outgoing-rendezvous') {
				if (pendingCandidates.length < MAX_PENDING_ICE_CANDIDATES) {
					pendingCandidates.push(init);
				}
				return;
			}
			if (state !== 'outgoing-connecting' && state !== 'incoming-connecting' && state !== 'ice-connected') {
				throw new Error('ICE candidate not expected in current call state');
			}
			await ensureConnection().addIceCandidate(init).then(() => {
				trace('addIceCandidate succeeded');
			}).catch((err) => {
				trace(`addIceCandidate failed: ${err.message}`);
			});
		},
		async restartIce() {
			if (iceRestartUsed || !connection || state !== 'outgoing-connecting') throw new Error('ICE restart unavailable');
			iceRestartUsed = true;
			const offer = await connection.createOffer({ iceRestart: true });
			await connection.setLocalDescription(offer);
			await config.onSignal({ signal: offer, privacyMode: config.privacyMode });
		},
		async end() {
			if (state !== 'ending' && state !== 'ended') move('end');
			localStream?.getTracks().forEach((track) => track.stop());
			connection?.close();
			connection = undefined;
			localStream = undefined;
			pendingOffer = undefined;
			pendingCandidates = [];
			controlChannel = undefined;
			challengeRequested = false;
			finishSent = false;
			localChallenge = undefined;
			if (finishTimeout) clearTimeout(finishTimeout);
			finishTimeout = undefined;
			if (statsInterval) clearInterval(statsInterval);
			statsInterval = undefined;
			if (state === 'ending') move('cleanup');
		},
		toggleAudio(enabled: boolean) {
			if (!localStream) return;
			for (const track of localStream.getAudioTracks()) {
				track.enabled = enabled;
			}
		},
		toggleVideo(enabled: boolean) {
			if (!localStream) return;
			for (const track of localStream.getVideoTracks()) {
				track.enabled = enabled;
			}
		}
	};
}
