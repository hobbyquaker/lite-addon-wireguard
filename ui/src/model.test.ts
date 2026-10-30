import {describe, expect, it} from 'vitest';

import {deviceState, endpointSuggestions, formatAge, formatBytes, looksLikeKey, type Device, type DeviceStatus, type Facts} from './model.js';

const t = (k: string, p?: Record<string, string | number>) => k.replace('{n}', String(p?.n ?? ''));

describe('model', () => {
    it('formats bytes', () => {
        expect(formatBytes(0)).toBe('0 B');
        expect(formatBytes(999)).toBe('999 B');
        expect(formatBytes(1234)).toBe('1.2 kB');
        expect(formatBytes(123456)).toBe('123 kB');
        expect(formatBytes(5_600_000)).toBe('5.6 MB');
        expect(formatBytes(-1)).toBe('–');
    });
    it('formats ages', () => {
        const now = 1_000_000_000;
        expect(formatAge(0, now, t)).toBe('never');
        expect(formatAge(now - 5000, now, t)).toBe('5 s ago');
        expect(formatAge(now - 5 * 60_000, now, t)).toBe('5 min ago');
        expect(formatAge(now - 3 * 3_600_000, now, t)).toBe('3 h ago');
        expect(formatAge(now - 2 * 86_400_000, now, t)).toBe('2 d ago');
    });
    it('derives the state', () => {
        const d: Device = {id: 'a', name: 'a', public_key: 'k', address: '10.77.0.2', enabled: true, has_psk: false, key_source: 'system', created: 0};
        const live = (h: number, c: boolean): DeviceStatus => ({id: 'a', enabled: true, connected: c, last_handshake: h, rx_bytes: 0, tx_bytes: 0, connections: 0});
        expect(deviceState(d, undefined)).toBe('never');
        expect(deviceState(d, live(0, false))).toBe('never');
        expect(deviceState(d, live(5, true))).toBe('connected');
        expect(deviceState(d, live(5, false))).toBe('idle');
        expect(deviceState({...d, enabled: false}, live(5, true))).toBe('disabled');
    });
    it('recognises keys', () => {
        expect(looksLikeKey('bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8=')).toBe(true);
        expect(looksLikeKey(' bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8= ')).toBe(true);
        expect(looksLikeKey('bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8')).toBe(false);
        expect(looksLikeKey('')).toBe(false);
    });
    it('suggests endpoints', () => {
        const f: Facts = {checked: true, token_ok: true, scopes: [], backup_unencrypted: false, hostname: 'ccu', domain: 'home.lan', addresses: ['192.168.1.5', '2001:db8::5'], at: 0};
        expect(endpointSuggestions(f)).toEqual(['ccu.home.lan', '192.168.1.5', '[2001:db8::5]']);
        expect(endpointSuggestions(undefined)).toEqual([]);
    });
});
