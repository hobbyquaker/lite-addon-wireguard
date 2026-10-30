<script lang="ts">
    // The server: its state, the settings, the key, and how the devices reach this system.
    import {untrack} from 'svelte';
    import {copyText} from 'occulite-ui/clipboard';
    import {t} from 'occulite-ui/i18n';
    import type {NoticesStore} from 'occulite-ui/notices';

    import ConfirmDialog from './ConfirmDialog.svelte';
    import ImportDialog from './ImportDialog.svelte';
    import {del, post, put} from './api.js';
    import {endpointSuggestions, formatAge, formatBytes, settingsOf, type Config, type Facts, type ServerSettings, type Status} from './model.js';

    let {config, status, facts, notices, onchanged}: {config: Config; status: Status | undefined; facts: Facts | undefined; notices: NoticesStore; onchanged: (c: Config) => void} = $props();

    let form = $state<ServerSettings>(untrack(() => settingsOf(config.server)));
    let busy = $state(false);
    let confirmKey = $state(false);
    let confirmRemoveClient = $state(false);
    let importOpen = $state(false);
    let host = $state<HTMLElement | undefined>();
    const client = $derived(config.mode === 'client');
    const now = $derived(status?.now ?? Date.now());
    const clientState = $derived(!config.server.enabled ? 'off' : status?.error ? 'error' : !status?.client?.last_handshake ? 'never' : now - status.client.last_handshake < 3 * 60_000 ? 'connected' : 'idle');

    $effect(() => {
        form = settingsOf(config.server);
    });

    const dirty = $derived(JSON.stringify(form) !== JSON.stringify(settingsOf(config.server)));
    const suggestions = $derived(endpointSuggestions(facts));
    const tunnelState = $derived(!config.server.enabled ? 'off' : status?.running ? 'running' : status?.error ? 'error' : 'off');

    async function save() {
        busy = true;
        try {
            onchanged(await put<Config>('api/v1/server', form));
            notices.push('info', t('Saved.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        } finally {
            busy = false;
        }
    }

    async function regenerate() {
        confirmKey = false;
        busy = true;
        try {
            onchanged(await post<Config>('api/v1/server/regenerate-key'));
            notices.push('warn', t('The key was replaced. Every device needs a new configuration.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        } finally {
            busy = false;
        }
    }

    async function copyKey(key: string) {
        const r = await copyText(key, {host});
        notices.push(r === 'failed' ? 'warn' : 'info', r === 'failed' ? t('The clipboard is not available here; select the text and copy it.') : t('Copied.'));
    }

    async function setMode(mode: 'server' | 'client') {
        if (mode === config.mode) return;
        if (mode === 'client' && !config.client) {
            importOpen = true;
            return;
        }
        busy = true;
        try {
            onchanged(await put<Config>('api/v1/mode', {mode}));
            notices.push('info', t('Saved.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        } finally {
            busy = false;
        }
    }

    async function removeClient() {
        confirmRemoveClient = false;
        busy = true;
        try {
            onchanged(await del<Config>('api/v1/client'));
            notices.push('info', t('Removed.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        } finally {
            busy = false;
        }
    }
</script>

<section class="wg-section" data-testid="mode" bind:this={host}>
    <h2>{t('Mode')}</h2>
    <div class="wg-radios">
        <label class="wg-check"><input type="radio" name="mode" value="server" checked={!client} onchange={() => setMode('server')} disabled={busy} data-testid="mode-server" /> {t('Server: this system listens, your devices connect to it (a port forward on the router)')}</label>
        <label class="wg-check"><input type="radio" name="mode" value="client" checked={client} onchange={() => setMode('client')} disabled={busy} data-testid="mode-client" /> {t('Client: this system connects to a WireGuard server elsewhere (a VPS, a router), your devices come through that server - no open port here')}</label>
    </div>
</section>

{#if client && config.client}
<section class="wg-section" data-testid="client">
    <h2>{t('Connection')}</h2>
    <div class="wg-kv">
        <span>{t('Tunnel')}</span>
        <span class="wg-row">
            <span class="wg-pill" class:ok={clientState === 'connected'} class:warn={clientState === 'idle'} class:bad={clientState === 'error'} class:off={clientState === 'off'} data-testid="client-state">{t('client.' + clientState)}</span>
            {#if status?.client}<span class="wg-muted wg-small">{t('Last handshake')}: {formatAge(status.client.last_handshake, now, t)} · ↓{formatBytes(status.client.rx_bytes)} ↑{formatBytes(status.client.tx_bytes)}</span>{/if}
        </span>
        <span>{t('Server')}</span>
        <span class="wg-mono">{config.client.endpoint}</span>
        <span>{t("This system's tunnel address")}</span>
        <span class="wg-mono">{config.client.address}</span>
        <span>{t('Devices that may reach this system')}</span>
        <span class="wg-mono">{config.client.allowed_ips.join(', ')}</span>
        <span>{t("This system's public key")}</span>
        <span class="wg-row"><span class="wg-mono wg-break" data-testid="client-public-key">{config.client.public_key}</span><button class="hmm-button" onclick={() => copyKey(config.client!.public_key)}>{t('Copy')}</button></span>
        <span>{t('Preshared key')}</span>
        <span>{config.client.has_psk ? t('yes') : t('no')} · {t('Keepalive (s)')}: {config.client.keepalive || t('off')}</span>
    </div>
    <div class="wg-actions">
        <button class="hmm-button" onclick={() => (importOpen = true)} disabled={busy} data-testid="client-import">{t('Import another configuration…')}</button>
        <span class="wg-spacer"></span>
        <button class="hmm-button wg-danger" onclick={() => (confirmRemoveClient = true)} disabled={busy} data-testid="client-remove">{t('Remove the configuration…')}</button>
    </div>
    <p class="wg-help">{t("The server must know this system as a peer with the public key above and route the devices' traffic for this system's tunnel address to it; the configuration file it made for this system says so. Through the tunnel the devices reach http://{address}/ - this system alone.", {address: config.client.address})}</p>
    <div class="wg-form">
        <label class="wg-check"><input type="checkbox" bind:checked={form.enabled} data-testid="server-enabled" /> {t('Tunnel on')}</label>
    </div>
    <div class="wg-actions">
        <button class="hmm-button wg-primary" disabled={!dirty || busy} onclick={save} data-testid="server-save">{t('Save')}</button>
    </div>
</section>

<section class="wg-section wg-section-wide" data-testid="mapped">
    <h2>{t('Devices seen')}</h2>
    <p class="wg-help">{t('The devices come with addresses of the server\'s network. This system sees each of them under a fixed address from {block} instead - the login lockout, the address ranges of API tokens and the journal use that one; here both are shown. The mapping is kept across restarts; when the block is full, the device not seen for the longest time gives its address up.', {block: '10.77.1.0/24'})}</p>
    {#if !status?.mapped?.length}
        <p class="wg-muted" data-testid="no-mapped">{t('No device has connected yet.')}</p>
    {:else}
        <table class="wg-grid">
            <thead><tr><th>{t('Address in the tunnel')}</th><th>{t('Seen by this system as')}</th><th>{t('Last seen')}</th><th>{t('Connections')}</th></tr></thead>
            <tbody>
                {#each status.mapped as m (m.real)}
                    <tr><td class="wg-mono">{m.real}</td><td class="wg-mono">{m.mapped}</td><td class="wg-nowrap wg-age">{formatAge(m.last_seen, now, t)}</td><td>{m.connections}</td></tr>
                {/each}
            </tbody>
        </table>
    {/if}
</section>

<section class="wg-section" data-testid="howto-client">
    <details class="wg-details">
        <summary>{t('A WireGuard server for this system (a VPS)')}</summary>
        <ol class="wg-howto">
            <li>{t('howto.client.1')}</li>
            <li>{t('howto.client.2')}</li>
            <li>{t('howto.client.3')}</li>
            <li>{t('howto.client.4')}</li>
        </ol>
        <p class="wg-help">{t('howto.client.5')}</p>
    </details>
</section>
{:else}
<section class="wg-section" data-testid="server-status">
    <h2>{t('Status')}</h2>
    <div class="wg-kv">
        <span>{t('Tunnel')}</span>
        <span><span class="wg-pill" class:ok={tunnelState === 'running'} class:bad={tunnelState === 'error'} class:off={tunnelState === 'off'} data-testid="tunnel-state">{t(tunnelState)}</span></span>
        <span>{t('Listen port (UDP)')}</span>
        <span class="wg-mono">{config.server.listen_port}</span>
        <span>{t('Firewall')}</span>
        <span class="wg-row">
            <span class="wg-pill" class:ok={facts?.port_open === true} class:bad={facts?.port_open === false} data-testid="port-state">{facts?.port_open === undefined ? t('unknown') : facts.port_open ? t('open') : t('closed')}</span>
            <span class="wg-muted wg-small">{t('The switch is on the Addons page, under this addon.')} <a href="/addons" target="_top">{t('Addons page')}</a></span>
        </span>
        <span>{t('Tunnel network')}</span>
        <span class="wg-mono">{config.server.network} <span class="wg-muted">· {t('this system {address}', {address: config.server.address})}</span></span>
        <span>{t("This system's public key")}</span>
        <span class="wg-row"><span class="wg-mono wg-break" data-testid="public-key">{config.server.public_key}</span><button class="hmm-button" onclick={() => copyKey(config.server.public_key)}>{t('Copy')}</button></span>
        <span>{t('Connections')}</span>
        <span>{t('{n} open, {total} since the start', {n: status?.connections ?? 0, total: status?.forwarded ?? 0})}</span>
    </div>
</section>

<section class="wg-section" data-testid="server-settings">
    <h2>{t('Settings')}</h2>
    <div class="wg-form">
        <label class="wg-check"><input type="checkbox" bind:checked={form.enabled} data-testid="server-enabled" /> {t('Tunnel on')}</label>
        <p class="wg-help">{t('Off, no UDP port is open and no device can connect; the devices and keys stay.')}</p>
        <label for="sv-port">{t('Listen port (UDP)')}</label>
        <input class="hmm-input wg-narrow" id="sv-port" type="number" min="1024" max="65535" bind:value={form.listen_port} data-testid="server-port" />
        <p class="wg-help">{t('The firewall switch on the Addons page opens {port}; another port needs a rule of its own on the Firewall page. The router forwards the same port.', {port: config.defaults.listen_port})}</p>
        <label for="sv-net">{t('Tunnel network')}</label>
        <input class="hmm-input wg-mono" id="sv-net" type="text" bind:value={form.network} maxlength="18" spellcheck="false" data-testid="server-network" />
        <p class="wg-help">{t('An IPv4 network, /16 to /29; this system takes the first address, the devices the following ones. Changing it moves the devices along; their configurations must be made again.')}</p>
        <label for="sv-endpoint">{t('Public endpoint')}</label>
        <input class="hmm-input" id="sv-endpoint" type="text" bind:value={form.endpoint} maxlength="260" spellcheck="false" autocomplete="off" list="sv-endpoint-list" placeholder="myhome.dyndns.example" data-testid="server-endpoint" />
        <datalist id="sv-endpoint-list">
            {#each suggestions as s (s)}<option value={s}></option>{/each}
        </datalist>
        <p class="wg-help">{t('The name or address the devices dial from the internet: your DynDNS name, a fixed address. Without a port the listen port is used. Goes into every device configuration made from now on.')}</p>
        <label for="sv-keepalive">{t('Keepalive (s)')}</label>
        <input class="hmm-input wg-narrow" id="sv-keepalive" type="number" min="0" max="3600" bind:value={form.keepalive} data-testid="server-keepalive" />
        <p class="wg-help">{t('PersistentKeepalive in the device configurations: a packet every n seconds keeps the path through the router open. 25 is usual; 0 switches it off.')}</p>
    </div>
    <div class="wg-actions">
        <button class="hmm-button wg-primary" disabled={!dirty || busy} onclick={save} data-testid="server-save">{t('Save')}</button>
        <span class="wg-spacer"></span>
        <span class="wg-muted wg-small">{t('Key of this system')}</span>
        <button class="hmm-button wg-danger" disabled={busy} onclick={() => (confirmKey = true)} data-testid="server-newkey">{t('New key…')}</button>
    </div>
</section>

<section class="wg-section" data-testid="howto">
    <details class="wg-details" open={config.devices.length === 0}>
        <summary>{t('How the devices reach this system')}</summary>
        <ol class="wg-howto">
            <li>{t('howto.1', {port: config.server.listen_port})}</li>
            <li>{t('howto.2', {port: config.server.listen_port, addresses: facts?.addresses.length ? facts.addresses.join(', ') : '…'})}</li>
            <li>{t('howto.3')}</li>
            <li>{t('howto.4', {address: config.server.address})}</li>
        </ol>
        <p class="wg-help">{t('howto.5')}</p>
    </details>
</section>
{/if}

<ImportDialog open={importOpen} onclose={() => (importOpen = false)} onsaved={(c) => ((importOpen = false), onchanged(c), notices.push('info', t('The configuration was imported; this system connects to the server now.')))} />
<ConfirmDialog
    open={confirmRemoveClient}
    title={t('Remove the server configuration?')}
    message={t('This system stops connecting to the server and returns to the server mode. The server keeps this system as a peer until you remove it there.')}
    confirmLabel={t('Remove')}
    danger
    testId="confirm-remove-client"
    onconfirm={removeClient}
    onclose={() => (confirmRemoveClient = false)}
/>
<ConfirmDialog
    open={confirmKey}
    title={t('Make a new key for this system?')}
    message={t('Every device configuration made so far stops working: each device needs a new configuration (the public key of this system changes). Do this when the key may have leaked.')}
    confirmLabel={t('Make a new key')}
    danger
    testId="confirm-newkey"
    onconfirm={regenerate}
    onclose={() => (confirmKey = false)}
/>
