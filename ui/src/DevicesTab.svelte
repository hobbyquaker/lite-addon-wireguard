<script lang="ts">
    // The devices: one row each with its live state, the add dialog, edit and remove.
    import {t} from 'occulite-ui/i18n';
    import type {NoticesStore} from 'occulite-ui/notices';

    import AddDeviceDialog from './AddDeviceDialog.svelte';
    import ConfirmDialog from './ConfirmDialog.svelte';
    import DeviceDialog from './DeviceDialog.svelte';
    import {del} from './api.js';
    import {deviceState, formatAge, formatBytes, type Config, type Device, type DeviceStatus, type Status} from './model.js';

    let {config, status, notices, now, onchanged}: {config: Config; status: Status | undefined; notices: NoticesStore; now: number; onchanged: (c: Config) => void} = $props();

    let addOpen = $state(false);
    let editing = $state<Device | undefined>();
    let removing = $state<Device | undefined>();

    function liveOf(d: Device): DeviceStatus | undefined {
        return status?.devices.find((s) => s.id === d.id);
    }

    // the server's clock, moved on by the page's own ticks since the answer
    let loaded = $state(Date.now());
    $effect(() => {
        if (status) loaded = Date.now();
    });
    const serverNow = $derived(status ? status.now + (now - loaded) : now);

    const hints: Record<string, string> = {
        connected: 'A handshake within the last three minutes: the device is connected.',
        idle: 'The device connected before, but not within the last three minutes.',
        never: 'The device has never connected.',
        disabled: 'The device is disabled: it cannot connect until you enable it.',
    };

    async function remove() {
        const d = removing;
        removing = undefined;
        if (!d) return;
        try {
            onchanged(await del<Config>(`api/v1/devices/${encodeURIComponent(d.id)}`));
            notices.push('info', t('Removed.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        }
    }
</script>

<section class="wg-section wg-section-wide" data-testid="devices">
    <div class="wg-section-head">
        <h2>{t('Devices')}</h2>
        <button class="hmm-button wg-primary" onclick={() => (addOpen = true)} data-testid="device-add">{t('Add device')}</button>
    </div>
    {#if config.devices.length === 0}
        <p class="wg-muted" data-testid="no-devices">{t('No devices yet. Add one: the key is made here and shown once as a QR code for the WireGuard app, or you paste the public key of a key the device made itself.')}</p>
    {:else}
        <table class="wg-grid wg-devices">
            <thead><tr><th>{t('Name')}</th><th>{t('State')}</th><th>{t('Tunnel address')}</th><th>{t('Last handshake')}</th><th>{t('Traffic')}</th><th>{t('Endpoint')}</th><th></th></tr></thead>
            <tbody>
                {#each config.devices as d (d.id)}
                    {@const live = liveOf(d)}
                    {@const st = deviceState(d, live)}
                    <tr class:wg-row-disabled={!d.enabled} data-testid="device-{d.id}">
                        <td>
                            <div class="wg-name" title={d.public_key}>{d.name}</div>
                            <div class="wg-faint wg-nowrap">{d.key_source === 'system' ? t('key made on the system') : t('own key')}{d.has_psk ? ' · ' + t('preshared key') : ''}</div>
                        </td>
                        <td><span class="wg-pill" class:ok={st === 'connected'} class:warn={st === 'idle'} class:off={st === 'disabled'} title={t(hints[st]!)} data-testid="state-{d.id}">{t('state.' + st)}</span></td>
                        <td class="wg-mono wg-nowrap">{d.address}</td>
                        <td class="wg-nowrap wg-age" data-testid="handshake-{d.id}">{live ? formatAge(live.last_handshake, serverNow, t) : t('never')}</td>
                        <td class="wg-nowrap wg-traffic" title="{t('received')} / {t('sent')}">
                            <span class="wg-arrow">↓</span>{formatBytes(live?.rx_bytes ?? 0)} <span class="wg-arrow">↑</span>{formatBytes(live?.tx_bytes ?? 0)}
                            {#if live?.connections}<span class="wg-faint"> · {t('{n} connections', {n: live.connections})}</span>{/if}
                        </td>
                        <td class="wg-mono wg-endpoint" title={live?.endpoint ?? ''}>{live?.endpoint ?? '–'}</td>
                        <td class="wg-cell-actions">
                            <button class="hmm-button" onclick={() => (editing = d)} data-testid="edit-{d.id}">{t('Edit')}</button>
                            <button class="hmm-button" onclick={() => (removing = d)} data-testid="remove-{d.id}">{t('Remove')}</button>
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    {/if}
</section>

<AddDeviceDialog open={addOpen} {config} {notices} onclose={() => (addOpen = false)} onsaved={onchanged} />
<DeviceDialog open={editing !== undefined} device={editing} onclose={() => (editing = undefined)} onsaved={(c) => ((editing = undefined), onchanged(c), notices.push('info', t('Saved.')))} />
<ConfirmDialog
    open={removing !== undefined}
    title={t('Remove device {name}?', {name: removing?.name ?? ''})}
    message={t('The device can no longer connect. Its configuration on the device becomes useless; a new device gets a new key.')}
    confirmLabel={t('Remove')}
    danger
    testId="confirm-remove"
    onconfirm={remove}
    onclose={() => (removing = undefined)}
/>
