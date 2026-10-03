import { createAuthenticatedSignaling } from '@securevoice/webrtc/signaling';
import { createDirectCall, type CallState, type DirectCall, type PrivacyMode, type MediaPreferences, type DirectCallConfig, type SignalPayload } from '@securevoice/webrtc';
import { createRendezvousTurnProvider } from '@securevoice/webrtc/turn';
import { generateAgreementKeyPair, importAgreementPublicKey, importSigningPublicKey } from '@securevoice/crypto';
import { ReplayGuard, encodeBase64Url } from '@securevoice/protocol';
import type { LocalIdentity, Contact } from './identity.js';
import { createHttpRendezvousClient, type RendezvousClient, type RendezvousMessage } from './rendezvous.js';
export type SessionConfig = {
  identity: LocalIdentity;
  rendezvousUrl: string;
  turnAuthToken?: string;
  onIncomingCall: (caller: Contact, accept: (mediaPreferences?: MediaPreferences) => void, reject: () => void) => void;
  onCallStateChange: (state: CallState) => void;
  onLocalStream?: (stream: MediaStream) => void;
  onRemoteStream: (stream: MediaStream) => void;
  onTrace: (event: string) => void;
  resolveContact: (keyId: string) => Promise<Contact | undefined>;
};

export class SessionManager {
  private activeCall?: DirectCall;
  private polling = true;
  private rendezvous: RendezvousClient;
  private replayGuard = new ReplayGuard();
  
  constructor(private config: SessionConfig) {
    this.rendezvous = createHttpRendezvousClient(config.rendezvousUrl);
    void this.pollLoop();
  }

  stop() {
    this.polling = false;
  }

  private trace(event: string) {
    this.config.onTrace(`[${new Date().toLocaleTimeString()}] ${event}`);
  }

  private async pollLoop() {
    while (this.polling) {
      try {
        if (!this.activeCall || !this.activeSignaling) {
          const messages = await this.rendezvous.get(this.config.identity.keyId, 10);
          for (const msg of messages) {
            await this.handleIncomingMessage(msg);
          }
        } else {
          await this.activeSignaling.receive(async (payload) => {
            await this.handleSignal(payload);
          }, 10);
        }
      } catch (err) {
        console.error('Polling error', err);
        await new Promise(r => setTimeout(r, 2000));
      }
    }
  }

  private async handleSignal(payload: SignalPayload) {
    if (!this.activeCall) return;
    if ('type' in payload.signal) {
      if (payload.signal.type === 'answer') {
        this.trace('answer received');
        await this.activeCall.receiveAnswer(payload);
      } else if (payload.signal.type === 'rollback') {
        this.trace('hangup (rollback) received');
        await this.endCall(false); // End call without sending another rollback
      }
    } else if ('candidate' in payload.signal) {
      this.trace('ICE candidate received');
      await this.activeCall.receiveIceCandidate(payload);
    }
  }

  private activeSignaling?: ReturnType<typeof createAuthenticatedSignaling>;

  private async handleIncomingMessage(msg: RendezvousMessage) {
    if (!this.activeSignaling) {
      const { parseEncodedEnvelope } = await import('@securevoice/protocol');
      try {
        const parsed = parseEncodedEnvelope(msg.ciphertext);
        const contact = await this.config.resolveContact(parsed.header.senderKeyId);
        if (!contact) {
          this.trace(`[inbound] unknown sender ${parsed.header.senderKeyId.slice(0, 8)}… — not in contacts, ignoring`);
          return;
        }

        if (parsed.header.type === 'call-offer') {
          this.trace('incoming offer received');
          // Start a new inbound session
          await this.setupInboundCall(contact);
        }
      } catch (e) {
        const msg2 = e instanceof Error ? e.message : String(e);
        this.trace(`[inbound] envelope parse error: ${msg2}`);
      }
    }
  }

  private settingUpCall = false; // guard against concurrent setupInboundCall

  private async setupInboundCall(caller: Contact) {
    if (this.activeCall || this.settingUpCall) {
      this.trace(`[inbound] skipped – busy (activeCall=${!!this.activeCall}, settingUp=${this.settingUpCall})`);
      return;
    }
    this.settingUpCall = true;

    try {
      this.trace('[inbound] generating ephemeral key...');
      const ephemeralKeyPair = await generateAgreementKeyPair();
      const localEphRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey));
      this.trace('[inbound] ephemeral key ready');

      const resolveKey = async (id: string) => {
        const c = await this.config.resolveContact(id);
        if (!c) return undefined;
        return importSigningPublicKey(c.signingPublicJwk);
      };

      this.trace('[inbound] importing remote static key...');
      const remoteStatic = await importAgreementPublicKey(caller.agreementPublicJwk);
      this.trace('[inbound] remote static key ready');

      // The offer lives in OUR mailbox (callee's keyId), not the caller's.
      // But outbound signals (answer, ICE) must go to the CALLER's mailbox.
      this.activeSignaling = createAuthenticatedSignaling({
        mailboxId: this.config.identity.keyId,
        outboxId: caller.contactId,
        senderKeyId: this.config.identity.keyId,
        recipientKeyId: caller.contactId,
        role: 'recipient',
        signingPrivateKey: this.config.identity.signingKeyPair.privateKey,
        localStaticAgreementPrivateKey: this.config.identity.agreementKeyPair.privateKey,
        remoteStaticAgreementPublicKey: remoteStatic,
        localEphemeralKeyPair: ephemeralKeyPair,
        localEphemeralPublicKeyRawBase64: encodeBase64Url(localEphRaw),
        resolveSenderKey: resolveKey,
        rendezvous: this.rendezvous,
        replayGuard: this.replayGuard,
      });
      this.trace('[inbound] signaling created');

      const turnProvider = this.config.turnAuthToken
        ? createRendezvousTurnProvider(this.config.rendezvousUrl, this.config.turnAuthToken)
        : undefined;

      const callConfig: DirectCallConfig = {
        localKeyId: this.config.identity.keyId,
        remoteKeyId: caller.contactId,
        turnProvider,
        stunServers: ['stun:stun.l.google.com:19302'],
        onSignal: async (payload: SignalPayload) => {
          if ('type' in payload.signal && payload.signal.type === 'answer') this.trace('answer generated');
          if ('candidate' in payload.signal) this.trace('ICE candidate sent');
          await this.activeSignaling!.send(payload);
          if ('type' in payload.signal && payload.signal.type === 'answer') this.trace('answer delivered');
        },
        onStateChange: (state: CallState) => {
          this.trace(state);
          this.config.onCallStateChange(state);
          if (state === 'ended' || state === 'idle') {
            this.activeCall = undefined;
            this.activeSignaling = undefined;
          }
        },
        onLocalStream: this.config.onLocalStream,
        onRemoteStream: this.config.onRemoteStream
      };

      this.activeCall = createDirectCall(callConfig);
      this.trace('[inbound] DirectCall created');

      // Decode the offer from the initial message using our signaling layer (which also ACKs it).
      this.trace('[inbound] calling receive() to decrypt offer...');
      let offerPayload: SignalPayload | undefined;
      const initialCandidates: SignalPayload[] = [];
      await this.activeSignaling.receive(async (payload) => {
        const typeStr = 'type' in payload.signal ? payload.signal.type : 'candidate';
        this.trace(`[inbound] got payload type=${JSON.stringify(typeStr)}`);
        if (!offerPayload && payload.signal && 'type' in payload.signal && payload.signal.type === 'offer') {
          offerPayload = payload;
        } else if (payload.signal && 'candidate' in payload.signal) {
          initialCandidates.push(payload);
        }
      });
      this.trace(`[inbound] receive() done, offerPayload=${!!offerPayload}`);

      if (!offerPayload) {
        this.trace('[inbound] ERROR: no offer found in mailbox – aborting');
        this.activeCall = undefined;
        this.activeSignaling = undefined;
        return;
      }

      this.trace('[inbound] calling receiveOffer()...');
      await this.activeCall.receiveOffer(offerPayload);
      this.trace('incoming offer received – notifying UI');

      for (const candidate of initialCandidates) {
        this.trace('ICE candidate received (from initial batch)');
        await this.activeCall.receiveIceCandidate(candidate);
      }

      this.config.onIncomingCall(caller,
        async (mediaPreferences) => {
          this.trace('incoming call accepted');
          if (mediaPreferences) {
            callConfig.mediaPreferences = mediaPreferences;
          }
          await this.activeCall!.acceptIncoming();
        },
        async () => {
          this.trace('incoming call rejected');
          await this.activeCall!.end();
          this.activeCall = undefined;
          this.activeSignaling = undefined;
        }
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      this.trace(`[inbound] ERROR: ${msg}`);
      console.error('setupInboundCall error', e);
      this.activeCall = undefined;
      this.activeSignaling = undefined;
    } finally {
      this.settingUpCall = false;
    }
  }

  async dial(contact: Contact, privacyMode: PrivacyMode, mediaPreferences?: MediaPreferences) {
    if (this.activeCall) throw new Error('Call already active');
    this.trace('outgoing call created');

    const ephemeralKeyPair = await generateAgreementKeyPair();
    const localEphRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey));

    const resolveKey = async (id: string) => {
      const c = await this.config.resolveContact(id);
      if (!c) return undefined;
      return importSigningPublicKey(c.signingPublicJwk);
    };

    const remoteStatic = await importAgreementPublicKey(contact.agreementPublicJwk);

    const turnProvider = this.config.turnAuthToken
      ? createRendezvousTurnProvider(this.config.rendezvousUrl, this.config.turnAuthToken)
      : undefined;

    // Create signaling and call together to prevent a race condition where
    // pollLoop() sees activeSignaling=set but activeCall=undefined and
    // falls into the idle-poll branch for up to 10 seconds.
    const signalingInstance = createAuthenticatedSignaling({
      mailboxId: this.config.identity.keyId,
      outboxId: contact.contactId,
      senderKeyId: this.config.identity.keyId,
      recipientKeyId: contact.contactId,
      role: 'caller',
      signingPrivateKey: this.config.identity.signingKeyPair.privateKey,
      localStaticAgreementPrivateKey: this.config.identity.agreementKeyPair.privateKey,
      remoteStaticAgreementPublicKey: remoteStatic,
      localEphemeralKeyPair: ephemeralKeyPair,
      localEphemeralPublicKeyRawBase64: encodeBase64Url(localEphRaw),
      resolveSenderKey: resolveKey,
      rendezvous: this.rendezvous,
      replayGuard: this.replayGuard,
    });

    const callInstance = createDirectCall({
      localKeyId: this.config.identity.keyId,
      remoteKeyId: contact.contactId,
      privacyMode,
      turnProvider,
      stunServers: privacyMode === 'direct-preferred' ? ['stun:stun.l.google.com:19302'] : undefined,
      onSignal: async (payload) => {
        if ('type' in payload.signal && payload.signal.type === 'offer') this.trace('offer generated');
        if ('candidate' in payload.signal) this.trace('ICE candidate sent');
        try {
          await this.activeSignaling!.send(payload);
          if ('type' in payload.signal && payload.signal.type === 'offer') this.trace('offer delivered');
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e);
          this.trace(`signal send failed: ${errMsg}`);
          throw e;
        }
      },
      onStateChange: (state) => {
        this.trace(state);
        this.config.onCallStateChange(state);
        if (state === 'ended' || state === 'idle') {
          this.activeCall = undefined;
          this.activeSignaling = undefined;
        }
      },
      mediaPreferences,
      onLocalStream: this.config.onLocalStream,
      onRemoteStream: this.config.onRemoteStream
    });

    // Assign atomically — prevents pollLoop race condition
    this.activeSignaling = signalingInstance;
    this.activeCall = callInstance;

    let dialTimeout: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.activeCall.startOutgoing(),
        new Promise<never>((_, reject) => {
          dialTimeout = setTimeout(() => reject(new Error('startOutgoing timed out after 30s (waiting for camera/microphone or TURN)')), 30000);
        }),
      ]);
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e);
      this.trace(`dial error: ${errMsg}`);
      await this.endCall(false);
      throw e;
    } finally {
      if (dialTimeout) clearTimeout(dialTimeout);
    }
  }

  async endCall(sendRollback = true) {
    if (this.activeCall) {
      if (sendRollback && this.activeSignaling) {
        try {
          this.trace('sending hangup (rollback) signal...');
          await this.activeSignaling.send({ signal: { type: 'rollback' } });
        } catch (e) {
          console.warn('Failed to send rollback signal', e);
        }
      }
      await this.activeCall.end();
      this.activeCall = undefined;
      this.activeSignaling = undefined;
    }
  }

  toggleAudio(enabled: boolean) {
    this.activeCall?.toggleAudio(enabled);
  }

  toggleVideo(enabled: boolean) {
    this.activeCall?.toggleVideo(enabled);
  }
}
