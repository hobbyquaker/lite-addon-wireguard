<script lang="ts">
    // Imports the configuration a WireGuard server made for this system (the client mode): the
    // file is pasted as text; the daemon parses and stores it and switches to the client mode.
    import {Dialog} from 'occulite-ui';
    import {t} from 'occulite-ui/i18n';

    import {post} from './api.js';
    import type {Config} from './model.js';

    let {open, onclose, onsaved}: {open: boolean; onclose: () => void; onsaved: (c: Config) => void} = $props();

    let conf = $state('');
    let busy = $state(false);
    let error = $state('');

    $effect(() => {
        if (!open) return;
        conf = '';
        error = '';
    });

    const valid = $derived(/\[Interface\]/i.test(conf) && /\[Peer\]/i.test(conf));

    async function save() {
        busy = true;
        error = '';
        try {
            onsaved(await post<Config>('api/v1/client/import', {conf}));
        } catch (e) {
            error = (e as Error).message;
        } finally {
            busy = false;
        }
    }
</script>

<Dialog {open} title={t('Import the server configuration')} width="40rem" closable={!busy} {onclose} testId="import-dialog">
    <p class="wg-help">{t('Paste the configuration file the WireGuard server made for this system: [Interface] with the private key and the tunnel address it gave this system, [Peer] with the server\'s public key, its endpoint and the networks whose devices may reach this system (AllowedIPs). DNS, MTU and scripts in it are ignored; this system makes nothing but the web server reachable.')}</p>
    <textarea class="hmm-input wg-conf" rows="12" bind:value={conf} spellcheck="false" placeholder={'[Interface]\nPrivateKey = …\nAddress = 10.8.0.5/32\n\n[Peer]\nPublicKey = …\nEndpoint = vps.example.org:51820\nAllowedIPs = 10.8.0.0/24\nPersistentKeepalive = 25'} data-testid="import-conf"></textarea>
    <p class="wg-help">{t('The private key in it is stored on this system (0600, in the backup) and never shown again.')}</p>
    <p class="wg-error" role="alert" data-testid="import-error">{error}</p>
    {#snippet buttons()}
        <button class="hmm-button" onclick={onclose} disabled={busy}>{t('Cancel')}</button>
        <button class="hmm-button wg-primary" onclick={save} disabled={!valid || busy} data-testid="import-save">{t('Import')}</button>
    {/snippet}
</Dialog>
