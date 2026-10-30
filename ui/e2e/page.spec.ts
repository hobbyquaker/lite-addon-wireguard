import {expect, test} from '@playwright/test';

// One run through the page against the daemon on the fake system and the ingress stub: the empty
// start, the server settings, a device made on the system with its one-time configuration, an
// imported device, edit, disable, remove, the key regeneration behind its confirmation, the port
// banner. The steps depend on each other (one daemon, one configuration).
test.describe.configure({mode: 'serial'});

const FAKE = 'http://127.0.0.1:18080';

test('starts without devices and says so', async ({page}) => {
    await page.goto('./');
    await expect(page.getByTestId('no-devices')).toBeVisible();
    await expect(page.getByTestId('banner-endpoint')).toBeVisible();
    await expect(page.getByTestId('banner-port')).toBeVisible();
});

test('saves the server settings', async ({page}) => {
    await page.goto('./');
    await page.getByRole('tab', {name: /Server/}).click();
    await expect(page.getByTestId('tunnel-state')).toHaveText('running');
    await expect(page.getByTestId('port-state')).toHaveText('closed');
    await page.getByTestId('server-endpoint').fill('ccu.example.org');
    await page.getByTestId('server-keepalive').fill('25');
    await page.getByTestId('server-save').click();
    await expect(page.getByTestId('server-save')).toBeDisabled();
    await expect(page.getByTestId('banner-endpoint')).toHaveCount(0);
    await page.getByTestId('server-port').fill('80');
    await page.getByTestId('server-save').click();
    await expect(page.getByText(/1024/)).toBeVisible();
    await page.getByTestId('server-port').fill('51899');
    // the firewall switch flipped on the system: the banner goes
    await page.request.get(`${FAKE}/dev/set?port_open=1`);
    await page.getByRole('tab', {name: /Devices/}).click();
    await page.getByRole('tab', {name: /Server/}).click();
    await expect(page.getByTestId('port-state')).toHaveText('open', {timeout: 25_000});
    await expect(page.getByTestId('banner-port')).toHaveCount(0);
});

test('adds a device made on the system and shows its configuration once', async ({page}) => {
    await page.goto('./');
    await page.getByTestId('device-add').click();
    await page.getByTestId('device-name').fill('Pixel 7');
    await page.getByTestId('device-create').click();
    const conf = page.getByTestId('device-conf');
    await expect(conf).toBeVisible();
    const text = await conf.inputValue();
    expect(text).toContain('[Interface]');
    expect(text).toMatch(/PrivateKey = [A-Za-z0-9+/]{43}=/);
    expect(text).toContain('Address = 10.77.0.2/32');
    expect(text).toContain('Endpoint = ccu.example.org:51899');
    expect(text).toContain('AllowedIPs = 10.77.0.1/32');
    expect(text).toContain('PresharedKey = ');
    await expect(page.getByTestId('device-qr')).toHaveAttribute('src', /^data:image\/png;base64,/);
    // the dialog closes only once the user confirms
    await expect(page.getByTestId('device-done')).toBeDisabled();
    await page.getByTestId('device-confirmed').check();
    await page.getByTestId('device-done').click();
    await expect(page.getByTestId('device-pixel-7')).toBeVisible();
    await expect(page.getByTestId('state-pixel-7')).toHaveText('never yet');
    // the list never shows the private key
    expect(await page.content()).not.toContain(text.split('PrivateKey = ')[1]!.split('\n')[0]);
});

test('adds a device with its own key and shows the server side', async ({page}) => {
    await page.goto('./');
    await page.getByTestId('device-add').click();
    await page.getByTestId('device-name').fill('Laptop');
    await page.getByTestId('source-imported').check();
    await page.getByTestId('device-pubkey').fill('not a key');
    await expect(page.getByTestId('device-create')).toBeDisabled();
    await page.getByTestId('device-pubkey').fill('bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8=');
    await page.getByTestId('device-create').click();
    await expect(page.getByText('PublicKey', {exact: true})).toBeVisible();
    await expect(page.getByText('10.77.0.3/32')).toBeVisible();
    await page.getByTestId('device-done').click();
    await expect(page.getByTestId('device-laptop')).toBeVisible();
    // the same key again is refused
    await page.getByTestId('device-add').click();
    await page.getByTestId('device-name').fill('Laptop 2');
    await page.getByTestId('source-imported').check();
    await page.getByTestId('device-pubkey').fill('bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8=');
    await page.getByTestId('device-create').click();
    await expect(page.getByTestId('device-error')).toContainText('exists');
    await page.keyboard.press('Escape');
});

test('edits, disables and removes a device', async ({page}) => {
    await page.goto('./');
    await page.getByTestId('edit-laptop').click();
    await page.getByTestId('edit-name').fill('Laptop (work)');
    await page.getByTestId('edit-enabled').uncheck();
    await page.getByTestId('edit-save').click();
    await expect(page.getByTestId('device-laptop')).toContainText('Laptop (work)');
    await expect(page.getByTestId('state-laptop')).toHaveText('disabled');
    await page.getByTestId('remove-laptop').click();
    await page.getByTestId('confirm-remove-yes').click();
    await expect(page.getByTestId('device-laptop')).toHaveCount(0);
    await expect(page.getByTestId('device-pixel-7')).toBeVisible();
});

test('regenerates the key behind a confirmation', async ({page}) => {
    await page.goto('./');
    await page.getByRole('tab', {name: /Server/}).click();
    const before = await page.getByTestId('public-key').textContent();
    await page.getByTestId('server-newkey').click();
    await expect(page.getByTestId('confirm-newkey')).toBeVisible();
    await page.getByTestId('confirm-newkey-yes').click();
    await expect(page.getByTestId('public-key')).not.toHaveText(before!);
});

test('the backup notice', async ({page}) => {
    await page.request.get(`${FAKE}/dev/set?backup_unencrypted=1`);
    await page.goto('./');
    await expect(page.getByTestId('banner-backup')).toBeVisible({timeout: 25_000});
    await page.request.get(`${FAKE}/dev/set?backup_unencrypted=0`);
});

test('the client mode: import a server configuration, then back', async ({page}) => {
    await page.goto('./');
    await page.getByRole('tab', {name: /Server/}).click();
    await page.getByTestId('mode-client').check();
    await expect(page.getByTestId('import-dialog')).toBeVisible();
    await page.getByTestId('import-conf').fill('[Interface]\nPrivateKey = WAmgVYXkbT2bCtdcDwolI88/iTy4GNaH42zKFkaWBHg=\nAddress = 10.8.0.5/32\n\n[Peer]\nPublicKey = bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8=\nEndpoint = 127.0.0.1:51898\nAllowedIPs = 10.8.0.0/24\nPersistentKeepalive = 25\n');
    await page.getByTestId('import-save').click();
    await expect(page.getByTestId('client')).toBeVisible();
    await expect(page.getByRole('tab', {name: /Devices/})).toHaveCount(0);
    await expect(page.getByTestId('client')).toContainText('127.0.0.1:51898');
    await expect(page.getByTestId('client')).toContainText('10.8.0.0/24');
    await expect(page.getByTestId('client-state')).toHaveText('never yet', {timeout: 10_000});
    // a file that does not parse is refused with the line
    await page.getByTestId('client-import').click();
    await page.getByTestId('import-conf').fill('[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n');
    await page.getByTestId('import-save').click();
    await expect(page.getByTestId('import-error')).toContainText('line 2');
    await page.keyboard.press('Escape');
    await page.getByTestId('client-remove').click();
    await page.getByTestId('confirm-remove-client-yes').click();
    await expect(page.getByTestId('server-status')).toBeVisible();
    await expect(page.getByRole('tab', {name: /Devices/})).toBeVisible();
});
