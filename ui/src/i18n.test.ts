import {readdirSync, readFileSync} from 'node:fs';
import {describe, expect, it} from 'vitest';

import {MESSAGES} from './messages.js';

// every t('…') of the page has its German and English text
describe('messages', () => {
    it('covers every key', () => {
        const dir = process.cwd() + '/src/';
        const missing: string[] = [];
        for (const f of readdirSync(dir).filter((f) => f.endsWith('.svelte') || f === 'model.ts')) {
            const src = readFileSync(dir + f, 'utf8');
            for (const m of src.matchAll(/\bt\((?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")/g)) {
                const key = (m[1] ?? m[2]!).replace(/\\'/g, "'");
                if (key.endsWith('.') || /\.\s*\+/.test(key)) continue;
                const e = MESSAGES[key] as {de?: string; en?: string} | undefined;
                if (!e?.de || !e?.en) missing.push(`${f}: ${key}`);
            }
        }
        for (const k of ['connected', 'idle', 'never', 'disabled']) if (!MESSAGES['state.' + k]) missing.push('state.' + k);
        for (const k of ['running', 'off', 'error', 'open', 'closed', 'unknown']) if (!MESSAGES[k]) missing.push(k);
        for (let i = 1; i <= 5; i++) if (!MESSAGES['howto.' + i]) missing.push('howto.' + i);
        // the state hints are looked up by their English text
        for (const k of ['A handshake within the last three minutes: the device is connected.', 'The device connected before, but not within the last three minutes.', 'The device has never connected.', 'The device is disabled: it cannot connect until you enable it.']) if (!MESSAGES[k]) missing.push(k);
        expect(missing).toEqual([]);
    });
    it('never says "box"', () => {
        for (const [k, v] of Object.entries(MESSAGES)) {
            const e = v as {de: string; en: string};
            // FRITZ!Box is a product name, not the system
            expect(`${k} ${e.de} ${e.en}`.replace(/FRITZ!Box/g, 'FRITZ')).not.toMatch(/\bbox\b/i);
        }
    });
});
