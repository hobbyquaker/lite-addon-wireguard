<script lang="ts">
    // The page: the devices with their live state, and the server (status, settings, the key, the
    // router how-to). The banners on top say what keeps the tunnel from working.
    import {onMount} from 'svelte';
    import {Notices, Tabs, ThemeSwitch} from 'occulite-ui';
    import {i18n, t} from 'occulite-ui/i18n';
    import {NoticesStore} from 'occulite-ui/notices';
    import {cycleTheme, theme} from 'occulite-ui/theme';

    import DevicesTab from './DevicesTab.svelte';
    import ServerTab from './ServerTab.svelte';
    import {get} from './api.js';
    import type {Config, Facts, Status} from './model.js';

    const notices = new NoticesStore();
    let tab = $state('devices');
    let config = $state<Config | undefined>();
    let status = $state<Status | undefined>();
    let facts = $state<Facts | undefined>();
    let loadError = $state('');
    let now = $state(Date.now());

    async function loadConfig() {
        try {
            config = await get<Config>('api/v1/config');
            loadError = '';
        } catch (e) {
            loadError = (e as Error).message;
        }
    }

    async function loadStatus() {
        try {
            status = await get<Status>('api/v1/status');
        } catch (e) {
            loadError = (e as Error).message;
        }
    }

    async function loadFacts(refresh = false) {
        try {
            facts = await get<Facts>('api/v1/system' + (refresh ? '?refresh=1' : ''));
        } catch {
            /* the banners simply stay away */
        }
    }

    onMount(() => {
        void loadConfig();
        void loadStatus();
        void loadFacts();
        const poll = setInterval(() => void loadStatus(), 3000);
        const slow = setInterval(() => void loadFacts(), 20000);
        const tick = setInterval(() => (now = Date.now()), 1000);
        return () => {
            clearInterval(poll);
            clearInterval(slow);
            clearInterval(tick);
        };
    });

    function changed(c: Config) {
        config = c;
        void loadStatus();
        void loadFacts(true);
    }

    const client = $derived(config?.mode === 'client');
    const tabs = $derived(
        client
            ? [{id: 'server', label: t('Connection')}]
            : [
                  {id: 'devices', label: t('Devices'), ...(config && config.devices.length === 0 ? {badge: '!'} : {})},
                  {id: 'server', label: t('Server'), ...(config && config.server.enabled && config.server.endpoint === '' ? {badge: '!'} : {})},
              ],
    );
    $effect(() => {
        if (client && tab === 'devices') tab = 'server';
    });
    const portClosed = $derived(!!config?.server.enabled && !client && facts?.port_open === false);
</script>

<div class="wg-app" lang={i18n.language}>
    <header class="wg-header">
        <h1>{t('VPN (WireGuard)')}</h1>
        <Tabs {tabs} bind:active={tab} label={t('VPN (WireGuard)')} testId="tabs" />
        <span class="wg-spacer"></span>
        {#if config}<span class="wg-muted wg-small">{t('Version {v}', {v: config.version})}</span>{/if}
        {#if !theme.followsShell}
            <ThemeSwitch theme={theme.choice} onclick={cycleTheme} />
        {/if}
    </header>
    <div class="wg-banners">
        {#if loadError}
            <div class="wg-banner wg-banner-error" role="alert">{t('The page could not read the configuration: {error}', {error: loadError})}</div>
        {/if}
        {#if status?.error && config?.server.enabled}
            <div class="wg-banner wg-banner-error" role="alert" data-testid="banner-tunnel">{t('The tunnel is not running: {error}', {error: status.error})}</div>
        {/if}
        {#if status?.socket_error}
            <div class="wg-banner wg-banner-error" role="alert" data-testid="banner-socket">{t('The web server could not be reached through its ingress socket: {error}. The system needs openccu-lite 1.1.0-dev.6 or newer.', {error: status.socket_error})}</div>
        {/if}
        {#if portClosed && config}
            <div class="wg-banner wg-banner-warn" role="status" data-testid="banner-port">
                {t('The UDP port {port} is closed on the firewall. Open it on the Addons page (the switch under this addon), and forward it on your router.', {port: config.server.listen_port})}
                <a href="/addons" target="_top">{t('Addons page')}</a>
            </div>
        {/if}
        {#if facts?.backup_unencrypted}
            <div class="wg-banner wg-banner-warn" role="status" data-testid="banner-backup">
                {t('The backups of this system are not encrypted. The private key of this server is in every backup; whoever reads a backup can impersonate this system to your devices. Switch backup encryption on.')}
                <a href="/backup#encryption" target="_top">{t('Backup page')}</a>
            </div>
        {/if}
        {#if facts?.checked && !facts.token_ok}
            <div class="wg-banner wg-banner-warn" role="status" data-testid="banner-token">{t("The addon's token is not accepted by the system: {error}. The page cannot show the firewall and backup state.", {error: facts.error ?? ''})}</div>
        {/if}
        {#if config && config.server.enabled && !client && config.server.endpoint === ''}
            <div class="wg-banner wg-banner-info" role="status" data-testid="banner-endpoint">{t('No public endpoint is set yet. The devices need the name or address under which this system is reachable from the internet: set it under Server.')}</div>
        {/if}
    </div>
    <main class="wg-page">
        {#if config}
            {#if tab === 'devices' && !client}
                <DevicesTab {config} {status} {notices} {now} onchanged={changed} />
            {:else}
                <ServerTab {config} {status} {facts} {notices} onchanged={changed} />
            {/if}
        {:else if !loadError}
            <p class="wg-muted">{t('Loading…')}</p>
        {/if}
    </main>
    <Notices notices={notices.visible} ondismiss={(id) => notices.dismiss(id)} />
</div>
