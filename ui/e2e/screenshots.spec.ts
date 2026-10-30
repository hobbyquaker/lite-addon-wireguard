import {expect, test} from '@playwright/test';

// The readme's screenshots (SCREENSHOTS=1 npx playwright test screenshots): German, light and dark.
test.skip(!process.env.SCREENSHOTS, 'only on demand');
test.use({locale: 'de-DE', viewport: {width: 1200, height: 820}});

const FAKE = 'http://127.0.0.1:18080';

for (const scheme of ['light', 'dark'] as const) {
    test(`screenshots ${scheme}`, async ({page}) => {
        await page.emulateMedia({colorScheme: scheme});
        const suffix = scheme === 'dark' ? '-dunkel' : '';
        const out = (n: string) => `../docs/screenshots/${n}${suffix}.png`;
        await page.request.get(`${FAKE}/dev/set?port_open=1&backup_unencrypted=0`);
        await page.goto('./');
        await page.getByRole('tab', {name: /Server/}).click();
        if ((await page.getByTestId('server-endpoint').inputValue()) === '') {
            await page.getByTestId('server-endpoint').fill('zuhause.myfritz.net');
            await page.getByTestId('server-save').click();
            await expect(page.getByTestId('server-save')).toBeDisabled();
        }
        await page.getByRole('tab', {name: /Geräte/}).click();
        if (!(await page.getByTestId('device-pixel-7').count())) {
            await page.getByTestId('device-add').click();
            await page.getByTestId('device-name').fill('Pixel 7');
            await page.getByTestId('device-create').click();
            await expect(page.getByTestId('device-qr')).toBeVisible();
            await page.waitForTimeout(400);
            await page.screenshot({path: out('02-neues-geraet')});
            await page.getByTestId('device-confirmed').check();
            await page.getByTestId('device-done').click();
            await page.getByTestId('device-add').click();
            await page.getByTestId('device-name').fill('Laptop');
            await page.getByTestId('source-imported').check();
            await page.getByTestId('device-pubkey').fill('bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8=');
            await page.getByTestId('device-create').click();
            await page.getByTestId('device-done').click();
        } else {
            await page.getByTestId('device-add').click();
            await page.getByTestId('device-name').fill('Tablet');
            await page.getByTestId('device-create').click();
            await expect(page.getByTestId('device-qr')).toBeVisible();
            await page.waitForTimeout(400);
            await page.screenshot({path: out('02-neues-geraet')});
            await page.getByTestId('device-confirmed').check();
            await page.getByTestId('device-done').click();
            await page.getByTestId('remove-tablet').click();
            await page.getByTestId('confirm-remove-yes').click();
        }
        await page.waitForTimeout(600);
        await page.screenshot({path: out('01-geraete')});
        await page.getByRole('tab', {name: /Server/}).click();
        await page.waitForTimeout(400);
        await page.screenshot({path: out('03-server')});
    });
}
