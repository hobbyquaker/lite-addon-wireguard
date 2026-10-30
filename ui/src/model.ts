// The API's shapes and the page's pure helpers (tested in model.test.ts).

export interface ServerView {
    enabled: boolean;
    public_key: string;
    listen_port: number;
    network: string;
    address: string;
    endpoint: string;
    endpoint_for: string;
    keepalive: number;
}

export interface ServerSettings {
    enabled: boolean;
    listen_port: number;
    network: string;
    endpoint: string;
    keepalive: number;
}

export interface Device {
    id: string;
    name: string;
    public_key: string;
    address: string;
    enabled: boolean;
    has_psk: boolean;
    key_source: 'system' | 'imported';
    created: number;
}

export interface Config {
    server: ServerView;
    devices: Device[];
    defaults: {listen_port: number; network: string; keepalive: number};
    version: string;
}

export interface PeerStatus {
    endpoint?: string;
    last_handshake: number;
    rx_bytes: number;
    tx_bytes: number;
    connections: number;
}

export interface DeviceStatus extends PeerStatus {
    id: string;
    enabled: boolean;
    connected: boolean;
}

export interface Status {
    running: boolean;
    error?: string;
    listen_port: number;
    address: string;
    public_key: string;
    peers: Record<string, PeerStatus>;
    connections: number;
    forwarded: number;
    socket_error?: string;
    since?: number;
    devices: DeviceStatus[];
    now: number;
}

export interface Facts {
    checked: boolean;
    token_ok: boolean;
    scopes: string[];
    error?: string;
    port_open?: boolean;
    port_rule_for?: number;
    backup_unencrypted: boolean;
    hostname?: string;
    domain?: string;
    addresses: string[];
    at: number;
}

export interface NewDevice {
    name: string;
    key_source: 'system' | 'imported';
    public_key?: string;
    preshared_key?: string;
    psk?: boolean;
}

export interface Issued {
    device: Device;
    config: Config;
    client?: {conf: string; file_name: string; qr: string; endpoint_missing: boolean};
}

export function settingsOf(s: ServerView): ServerSettings {
    return {enabled: s.enabled, listen_port: s.listen_port, network: s.network, endpoint: s.endpoint, keepalive: s.keepalive};
}

/** 1.2 MB, 340 kB, 12 B - bytes with a unit, one decimal above a thousand. */
export function formatBytes(n: number): string {
    if (!Number.isFinite(n) || n < 0) return '–';
    const units = ['B', 'kB', 'MB', 'GB', 'TB'];
    let v = n;
    let i = 0;
    while (v >= 1000 && i < units.length - 1) {
        v /= 1000;
        i++;
    }
    return (i === 0 ? String(Math.round(v)) : v.toFixed(v >= 100 ? 0 : 1)) + ' ' + units[i];
}

/** The age of a moment as a short phrase; t translates the templates. */
export function formatAge(at: number, now: number, t: (k: string, p?: Record<string, string | number>) => string): string {
    if (!at) return t('never');
    const s = Math.max(0, Math.round((now - at) / 1000));
    if (s < 60) return t('{n} s ago', {n: s});
    if (s < 3600) return t('{n} min ago', {n: Math.floor(s / 60)});
    if (s < 86400) return t('{n} h ago', {n: Math.floor(s / 3600)});
    return t('{n} d ago', {n: Math.floor(s / 86400)});
}

/** The device's state for its pill: connected, idle (a handshake, but not within 3 minutes), never, disabled. */
export function deviceState(d: Device, st: DeviceStatus | undefined): 'connected' | 'idle' | 'never' | 'disabled' {
    if (!d.enabled) return 'disabled';
    if (!st || !st.last_handshake) return 'never';
    return st.connected ? 'connected' : 'idle';
}

/** A WireGuard key as the apps print it: 44 characters of base64 ending in "=". */
export function looksLikeKey(s: string): boolean {
    return /^[A-Za-z0-9+/]{43}=$/.test(s.trim());
}

/** The endpoint suggestions for the server form: the system's full name and its addresses. */
export function endpointSuggestions(f: Facts | undefined): string[] {
    if (!f) return [];
    const out: string[] = [];
    if (f.hostname) out.push(f.domain ? `${f.hostname}.${f.domain}` : f.hostname);
    for (const a of f.addresses) out.push(a.includes(':') ? `[${a}]` : a);
    return out;
}
