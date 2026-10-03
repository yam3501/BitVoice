export type TurnCredentialProvider = () => Promise<RTCIceServer[]>;

export function createRendezvousTurnProvider(rendezvousUrl: string, authToken: string): TurnCredentialProvider {
  return async () => {
    const res = await fetch(`${rendezvousUrl.replace(/\/+$/, '')}/v1/turn`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      signal: AbortSignal.timeout(5000)
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch TURN credentials: ${res.status}`);
    }

    let payload: unknown;
    try {
      payload = await res.json();
    } catch {
      throw new Error('Invalid JSON response from TURN endpoint');
    }

    if (!payload || typeof payload !== 'object') {
      throw new Error('Invalid response structure');
    }

    if (!Array.isArray((payload as { iceServers?: unknown }).iceServers)) {
      throw new Error('Missing or invalid iceServers array in response');
    }

    const iceServers: RTCIceServer[] = [];

    for (const server of (payload as { iceServers: unknown[] }).iceServers) {
      if (!server || typeof server !== 'object') {
        throw new Error('Invalid ICE server entry');
      }

      const srv = server as { urls?: unknown, username?: unknown, credential?: unknown };

      if (!Array.isArray(srv.urls)) {
        throw new Error('ICE server urls must be an array');
      }

      for (const url of srv.urls) {
        if (typeof url !== 'string') {
          throw new Error('ICE server url must be a string');
        }
        if (!url.startsWith('turn:') && !url.startsWith('turns:')) {
          throw new Error(`Invalid ICE server url scheme: ${url}`);
        }
        if (url.length > 1024) {
          throw new Error('ICE server url too long');
        }
      }

      if (typeof srv.username !== 'string' || srv.username.length > 256) {
        throw new Error('Invalid or missing ICE server username');
      }

      if (typeof srv.credential !== 'string' || srv.credential.length > 256) {
        throw new Error('Invalid or missing ICE server credential');
      }

      iceServers.push(srv as RTCIceServer);
    }

    return iceServers;
  };
}
