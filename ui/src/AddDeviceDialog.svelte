<script lang="ts">
    // Adds a device in two steps: the name and the key's origin, then - for a key made on the
    // system - the configuration, shown exactly once as a QR code and a file. For an imported key
    // the second step shows the server side the user enters on the device.
    import {Dialog} from 'occulite-ui';
    import {copyText} from 'occulite-ui/clipboard';
    import {t} from 'occulite-ui/i18n';
    import type {NoticesStore} from 'occulite-ui/notices';

    import {post} from './api.js';
    import {looksLikeKey, type Config, type Issued, type NewDevice} from './model.js';

    let {open, config, notices, onclose, onsaved}: {open: boolean; config: Config; notices: NoticesStore; onclose: () => void; onsaved: (c: Config) => void} = $props();

    let name = $state('');
    let source = $state<'system' | 'imported'>('system');
    let psk = $state(true);
    let publicKey = $state('');
    let preshared = $state('');
    let busy = $state(false);
    let error = $state('');
    let issued = $state<Issued | undefined>();
    let confirmed = $state(false);

    $effect(() => {
        if (!open) return;
        name = '';
        source = 'system';
        psk = true;
        publicKey = '';
        preshared = '';
        error = '';
        issued = undefined;
        confirmed = false;
    });

    const valid = $derived(name.trim() !== '' && (source === 'system' || (looksLikeKey(publicKey) && (preshared.trim() === '' || looksLikeKey(preshared)))));

    async function create() {
        busy = true;
        error = '';
        try {
            const body: NewDevice = {name: name.trim(), key_source: source};
            if (source === 'system') body.psk = psk;
            else {
                body.public_key = publicKey.trim();
                if (preshared.trim()) body.preshared_key = preshared.trim();
            }
            issued = await post<Issued>('api/v1/devices', body);
            onsaved(issued.config);
            notices.push('info', t('Device {name} added.', {name: issued.device.name}));
        } catch (e) {
            error = (e as Error).message;
        } finally {
            busy = false;
        }
    }

    function download() {
        if (!issued?.client) return;
        const blob = new Blob([issued.client.conf], {type: 'application/octet-stream'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = issued.client.file_name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    async function copy(text: string, host?: HTMLElement) {
        const r = await copyText(text, {host});
        if (r === 'failed') notices.push('warn', t('The clipboard is not available here; select the text and copy it.'));
        else notices.push('info', t('Copied.'));
    }

    let dialogEl = $state<HTMLElement | undefined>();
    const canClose = $derived(!busy && (!issued?.client || confirmed));
</script>

<Dialog {open} title={issued ? t('The configuration of {name}', {name: issued.device.name}) : t('New device')} width="40rem" closable={canClose} onclose={() => canClose && onclose()} testId="device-dialog">
    {#if !issued}
        <p class="wg-help">{t('A phone, a laptop, a program elsewhere. The name is for this list only.')}</p>
        <div class="wg-form">
            <label for="dv-name">{t('Name')}</label>
            <input class="hmm-input" id="dv-name" type="text" bind:value={name} maxlength="64" autocomplete="off" data-testid="device-name" />
            <span class="wg-label">{t('Key')}</span>
            <div class="wg-radios">
                <label class="wg-check"><input type="radio" name="source" value="system" bind:group={source} data-testid="source-system" /> {t('Make the key here and show the configuration once (QR code for the WireGuard app, or a file)')}</label>
                <p class="wg-help wg-indent">{t('Recommended for phones: scan the code, done. The private key is never stored on this system.')}</p>
                <label class="wg-check"><input type="radio" name="source" value="imported" bind:group={source} data-testid="source-imported" /> {t('Use a key the device made itself: paste its public key')}</label>
                <p class="wg-help wg-indent">{t('Recommended for laptops and servers: nothing secret leaves the device. You enter the server side there yourself (public key, endpoint, allowed IPs are shown after saving).')}</p>
            </div>
            {#if source === 'system'}
                <label class="wg-check"><input type="checkbox" bind:checked={psk} data-testid="device-psk" /> {t('Also a preshared key (an extra secret both sides hold; recommended)')}</label>
            {:else}
                <label for="dv-pub">{t("The device's public key")}</label>
                <input class="hmm-input wg-mono" id="dv-pub" type="text" bind:value={publicKey} maxlength="44" spellcheck="false" autocomplete="off" class:wg-invalid={publicKey !== '' && !looksLikeKey(publicKey)} data-testid="device-pubkey" />
                <p class="wg-help">{t('44 characters ending in =, as wg pubkey prints it.')}</p>
                <label for="dv-psk">{t('Preshared key (optional, as the device has it)')}</label>
                <input class="hmm-input wg-mono" id="dv-psk" type="text" bind:value={preshared} maxlength="44" spellcheck="false" autocomplete="off" class:wg-invalid={preshared !== '' && !looksLikeKey(preshared)} data-testid="device-preshared" />
            {/if}
        </div>
        {#if config.server.endpoint === ''}
            <p class="wg-warning">{t('No public endpoint is set yet. The devices need the name or address under which this system is reachable from the internet: set it under Server.')}</p>
        {/if}
        <p class="wg-error" role="alert" data-testid="device-error">{error}</p>
    {:else if issued.client}
        <div class="wg-issued" bind:this={dialogEl}>
            <p class="wg-warning">{t('Shown once. Scan the code with the WireGuard app (Add tunnel → Scan from QR code) or download the file for WireGuard on a computer. When you close this, the private key is gone from this system for good.')}</p>
            {#if issued.client.endpoint_missing}
                <p class="wg-warning">{t('The configuration carries no endpoint because none is set under Server yet; enter the address in the app by hand, or set the endpoint first and add the device again.')}</p>
            {/if}
            <div class="wg-issued-body">
                <img class="wg-qr" src={issued.client.qr} alt={t('QR code of the configuration')} width="320" height="320" data-testid="device-qr" />
                <div class="wg-conf-box">
                    <textarea class="hmm-input wg-conf" readonly rows="11" spellcheck="false" data-testid="device-conf">{issued.client.conf}</textarea>
                    <div class="wg-row">
                        <button class="hmm-button wg-primary" onclick={download} data-testid="device-download">{t('Download {file}', {file: issued.client.file_name})}</button>
                        <button class="hmm-button" onclick={() => copy(issued!.client!.conf, dialogEl)}>{t('Copy')}</button>
                    </div>
                </div>
            </div>
            <label class="wg-check wg-confirm"><input type="checkbox" bind:checked={confirmed} data-testid="device-confirmed" /> {t('I have scanned or saved the configuration')}</label>
        </div>
    {:else}
        <div class="wg-issued" bind:this={dialogEl}>
            <p class="wg-help">{t('The server side for the device')}</p>
            <p class="wg-help">{t('Enter these in the WireGuard configuration of the device, under [Peer]; its [Interface] gets the address and its own private key.')}</p>
            <div class="wg-kv wg-kv-compact">
                <span>PublicKey</span><span class="wg-mono wg-break">{config.server.public_key}</span>
                <span>Endpoint</span><span class="wg-mono">{config.server.endpoint_for || '–'}</span>
                <span>AllowedIPs</span><span class="wg-mono">{config.server.address}/32</span>
                {#if config.server.keepalive}<span>PersistentKeepalive</span><span class="wg-mono">{config.server.keepalive}</span>{/if}
                <span>Address</span><span class="wg-mono">{issued.device.address}/32</span>
            </div>
            <div class="wg-row">
                <button class="hmm-button" onclick={() => copy(`[Peer]\nPublicKey = ${config.server.public_key}\n${config.server.endpoint_for ? 'Endpoint = ' + config.server.endpoint_for + '\n' : ''}AllowedIPs = ${config.server.address}/32\n${config.server.keepalive ? 'PersistentKeepalive = ' + config.server.keepalive + '\n' : ''}`, dialogEl)}>{t('Copy')}</button>
            </div>
        </div>
    {/if}
    {#snippet buttons()}
        {#if !issued}
            <button class="hmm-button" onclick={onclose} disabled={busy}>{t('Cancel')}</button>
            <button class="hmm-button wg-primary" onclick={create} disabled={!valid || busy} data-testid="device-create">{t('Create')}</button>
        {:else}
            <button class="hmm-button wg-primary" onclick={onclose} disabled={!canClose} data-testid="device-done">{t('Close')}</button>
        {/if}
    {/snippet}
</Dialog>
