import {
  decryptEnvelope,
  encryptEnvelope,
  signEnvelope,
  verifyEnvelope,
} from '@securevoice/crypto';
import {
  encodeBase64Url,
  decodeBase64Url,
  type EnvelopeHeader,
  type SignedEnvelope,
} from '@securevoice/protocol';
import type { PrivacyMode, SignalPayload as WebrtcSignalPayload } from './index.js';

export type WebRtcSignal = RTCSessionDescriptionInit | RTCIceCandidateInit;
export type SignalingPayload = { callId: string; signal: WebRtcSignal; privacyMode?: PrivacyMode };
export type RendezvousMessage = { messageId: string; ciphertext: string; expiresAt: number; storedAt?: number };

export type RendezvousClient = {
  put(mailboxId: string, message: { messageId: string; ciphertext: string; expiresAt: number }): Promise<void>;
  get(mailboxId: string, waitSeconds?: number): Promise<RendezvousMessage[]>;
  ack(mailboxId: string, messageId: string): Promise<void>;
};

export type AuthenticatedSignalingConfig = {
  mailboxId: string;   // inbox — where we READ messages from
  outboxId?: string;   // where we SEND messages to (defaults to mailboxId if omitted)
  senderKeyId: string;
  recipientKeyId: string;
  signingPrivateKey: CryptoKey;
  
  role: 'caller' | 'recipient';
  localStaticAgreementPrivateKey: CryptoKey;
  remoteStaticAgreementPublicKey: CryptoKey;
  localEphemeralKeyPair: CryptoKeyPair;
  localEphemeralPublicKeyRawBase64: string;

  resolveSenderKey: (senderKeyId: string) => Promise<CryptoKey | undefined>;
  rendezvous: RendezvousClient;
  replayGuard: { accept(messageId: string, expiresAt: number, now?: number): void };
  now?: () => number;
};

const encoder = new TextEncoder();

function randomId(size: number): string {
  return encodeBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(size)));
}

function makeHeader(config: AuthenticatedSignalingConfig, type: EnvelopeHeader['type'], now: number, callId: string): EnvelopeHeader {
  return {
    version: 2,
    type,
    messageId: randomId(16),
    callId: callId,
    senderKeyId: config.senderKeyId,
    recipientKeyId: config.recipientKeyId,
    ephemeralPublicKey: config.localEphemeralPublicKeyRawBase64,
    issuedAt: now,
    expiresAt: now + 5 * 60 * 1000,
    nonce: randomId(12),
  };
}

function signalType(signal: WebRtcSignal): EnvelopeHeader['type'] {
  if ('candidate' in signal) return 'ice-candidate';
  if ('type' in signal && signal.type === 'offer') return 'call-offer';
  if ('type' in signal && signal.type === 'answer') return 'call-answer';
  return 'ice-candidate';
}

import { importAgreementPublicKeyRaw, deriveSharedSecret, deriveSessionKeys, type SessionKeys } from '@securevoice/crypto';

export function createAuthenticatedSignaling(config: AuthenticatedSignalingConfig) {
  const now = config.now ?? Date.now;
  let currentCallId: string | undefined;
  let remoteEphemeralPublicKeyBase64: string | undefined;
  let activeSessionKeys: SessionKeys | undefined;
  let preAnswerSessionKeys: SessionKeys | undefined;

  /**
   * Key derivation strategy:
   *
   * Before the answer is exchanged, both sides use a static-key-based derivation
   * (ECDH of caller_eph_priv × callee_static_pub = ECDH of callee_static_priv × caller_eph_pub).
   * This key is never cached so it can't be confused with the post-answer session key.
   *
   * After the callee sends the answer, both sides switch to an ephemeral-only key
   * (ECDH of caller_eph_priv × callee_eph_pub). This is stored in activeSessionKeys
   * and used for all subsequent messages.
   *
   * `isSending` lets us tell the two contexts apart:
   *   - isSending=false (receive): use static key for pre-answer messages, cached key after
   *   - isSending=true  (send):    use static key for offer/ICE, establish ephemeral key on first non-offer send
   */
  async function getSessionKeys(header: EnvelopeHeader, isSending: boolean): Promise<SessionKeys> {
    if (activeSessionKeys) return activeSessionKeys;

    if (config.role === 'caller') {
      if (!isSending && header.ephemeralPublicKey && header.type !== 'call-offer') {
        // Receiving answer/ICE from callee: establish forward-secret ephemeral session key.
        remoteEphemeralPublicKeyBase64 = header.ephemeralPublicKey;
        const remoteEphKey = await importAgreementPublicKeyRaw(decodeBase64Url(remoteEphemeralPublicKeyBase64));
        const secret = await deriveSharedSecret(config.localEphemeralKeyPair.privateKey, remoteEphKey);
        activeSessionKeys = await deriveSessionKeys(secret, header.callId!, config.role);
        return activeSessionKeys;
      }
      // Sending offer/ICE (pre-answer) OR receiving offer: use static-key derivation (not cached).
      if (preAnswerSessionKeys) return preAnswerSessionKeys;
      const secret = await deriveSharedSecret(config.localEphemeralKeyPair.privateKey, config.remoteStaticAgreementPublicKey);
      preAnswerSessionKeys = await deriveSessionKeys(secret, header.callId!, config.role);
      return preAnswerSessionKeys;
    } else {
      // recipient role
      if (!remoteEphemeralPublicKeyBase64 && header.ephemeralPublicKey) {
        remoteEphemeralPublicKeyBase64 = header.ephemeralPublicKey;
      }

      if (header.type === 'call-offer') {
        // Receiving the offer: use static-key derivation (not cached).
        const remoteEphKey = await importAgreementPublicKeyRaw(decodeBase64Url(remoteEphemeralPublicKeyBase64!));
        const secret = await deriveSharedSecret(config.localStaticAgreementPrivateKey, remoteEphKey);
        preAnswerSessionKeys = await deriveSessionKeys(secret, header.callId!, config.role);
        return preAnswerSessionKeys;
      }
      if (!remoteEphemeralPublicKeyBase64) throw new Error('Missing remote ephemeral key');
      const remoteEphKey = await importAgreementPublicKeyRaw(decodeBase64Url(remoteEphemeralPublicKeyBase64));
      if (isSending) {
        // Sending the answer (first send): establish forward-secret ephemeral session key.
        const secret = await deriveSharedSecret(config.localEphemeralKeyPair.privateKey, remoteEphKey);
        activeSessionKeys = await deriveSessionKeys(secret, header.callId!, config.role);
        return activeSessionKeys;
      }
      // Receiving ICE from caller before answer has been sent: use same static-key as the offer.
      // (Caller encrypted these with caller_eph_priv × callee_static_pub = callee_static_priv × caller_eph_pub)
      if (preAnswerSessionKeys) return preAnswerSessionKeys;
      const secret = await deriveSharedSecret(config.localStaticAgreementPrivateKey, remoteEphKey);
      preAnswerSessionKeys = await deriveSessionKeys(secret, header.callId!, config.role);
      return preAnswerSessionKeys;
    }
  }

  return {
    get currentCallId() { return currentCallId; },
    resetCallId(callId: string) {
      currentCallId = callId;
      activeSessionKeys = undefined;
      remoteEphemeralPublicKeyBase64 = undefined;
    },
    get activeCallId() {
      return currentCallId;
    },
    async send(payload: WebrtcSignalPayload): Promise<string> {
      if (!currentCallId) currentCallId = randomId(16);
      const type = signalType(payload.signal);
      const header = makeHeader(config, type, now(), currentCallId);
      const keys = await getSessionKeys(header, true);

      const sigPayload: SignalingPayload = { callId: currentCallId, signal: payload.signal, privacyMode: payload.privacyMode };
      const ciphertext = await encryptEnvelope(keys.sendingKey, encoder.encode(JSON.stringify(sigPayload)), header);
      const encoded = await signEnvelope(config.signingPrivateKey, { header, ciphertext });
      const envelope = JSON.parse(encoded) as SignedEnvelope;
      await config.rendezvous.put(config.outboxId ?? config.mailboxId, {
        messageId: envelope.header.messageId,
        ciphertext: encoded,
        expiresAt: envelope.header.expiresAt,
      });
      return envelope.header.messageId;
    },

    async receive(onPayload: (payload: WebrtcSignalPayload, sourceCallId: string) => Promise<void>, waitSeconds = 0): Promise<void> {
      const messages = await config.rendezvous.get(config.mailboxId, waitSeconds);
      const acks: Promise<void>[] = [];
      for (const message of messages) {
        try {
          const envelope = await verifyEnvelope(message.ciphertext, config.resolveSenderKey, config.replayGuard, now());
          
          if (envelope.header.type === 'call-offer' && !currentCallId) {
            currentCallId = envelope.header.callId!;
            remoteEphemeralPublicKeyBase64 = undefined;
            activeSessionKeys = undefined;
            preAnswerSessionKeys = undefined;
          }

          const keys = await getSessionKeys(envelope.header, false);
          const plaintext = await decryptEnvelope(keys.receivingKey, envelope.ciphertext, envelope.header);
          const payload = JSON.parse(new TextDecoder().decode(plaintext)) as SignalingPayload;
          const signalIsCandidate = payload.signal && 'candidate' in payload.signal;
          const signalHasDescription = payload.signal && 'type' in payload.signal && (payload.signal.type === 'offer' || payload.signal.type === 'answer' || payload.signal.type === 'rollback');
          if (payload.callId !== envelope.header.callId || !payload.signal || (!signalIsCandidate && !signalHasDescription)) throw new Error('invalid signaling payload');
          
          await onPayload({ signal: payload.signal, privacyMode: payload.privacyMode }, payload.callId);
          acks.push(config.rendezvous.ack(config.mailboxId, message.messageId));
        } catch (error: unknown) {
          if ((error as Error)?.name !== 'ReplayError') {
            console.warn('Failed to process rendezvous message (ignoring):', error);
          }
          acks.push(config.rendezvous.ack(config.mailboxId, message.messageId).catch(() => {}));
        }
      }
      await Promise.all(acks);
    },
  };
}

