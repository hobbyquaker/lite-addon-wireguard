<script lang="ts">
    // Renames or switches a device.
    import {Dialog} from 'occulite-ui';
    import {t} from 'occulite-ui/i18n';

    import {put} from './api.js';
    import type {Config, Device} from './model.js';

    let {open, device, onclose, onsaved}: {open: boolean; device: Device | undefined; onclose: () => void; onsaved: (c: Config) => void} = $props();

    let name = $state('');
    let enabled = $state(true);
    let busy = $state(false);
    let error = $state('');

    $effect(() => {
        if (!open || !device) return;
        name = device.name;
        enabled = device.enabled;
        error = '';
    });

    async function save() {
        if (!device) return;
        busy = true;
        error = '';
        try {
            onsaved(await put<Config>(`api/v1/devices/${encodeURIComponent(device.id)}`, {name: name.trim(), enabled}));
        } catch (e) {
            error = (e as Error).message;
        } finally {
            busy = false;
        }
    }
</script>

<Dialog {open} title={t('Device {name}', {name: device?.name ?? ''})} width="34rem" closable={!busy} {onclose} testId="edit-dialog">
    <div class="wg-form">
        <label for="ed-name">{t('Name')}</label>
        <input class="hmm-input" id="ed-name" type="text" bind:value={name} maxlength="64" autocomplete="off" data-testid="edit-name" />
        <label class="wg-check"><input type="checkbox" bind:checked={enabled} data-testid="edit-enabled" /> {t('Enabled')}</label>
        <p class="wg-help">{t('A disabled device keeps its key and address but cannot connect.')}</p>
        <span class="wg-label">{t('Tunnel address')}</span>
        <span class="wg-mono">{device?.address}</span>
        <span class="wg-label">{t('Public key')}</span>
        <span class="wg-mono wg-break">{device?.public_key}</span>
        <span class="wg-label">{t('Added since')}</span>
        <span>{device ? new Date(device.created).toLocaleString() : ''}</span>
    </div>
    <p class="wg-error" role="alert">{error}</p>
    {#snippet buttons()}
        <button class="hmm-button" onclick={onclose} disabled={busy}>{t('Cancel')}</button>
        <button class="hmm-button wg-primary" onclick={save} disabled={busy || name.trim() === ''} data-testid="edit-save">{t('Save')}</button>
    {/snippet}
</Dialog>
