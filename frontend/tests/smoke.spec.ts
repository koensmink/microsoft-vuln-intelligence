import { test, expect } from '@playwright/test';

test('dashboard keeps data sources only in the desktop sidebar', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'Microsoft Vulnerability Intelligence' })).toBeVisible();
  await expect(page.locator('aside').getByText('Data Sources')).toBeVisible();
  await expect(page.getByText('Data Sources')).toHaveCount(1);
  await expect(page.locator('main').getByText('Data Sources')).toHaveCount(0);
});

test('mobile navigation remains available without the desktop sidebar', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');

  await expect(page.locator('aside')).toBeHidden();
  await expect(page.getByRole('link', { name: /Overview/ })).toBeVisible();
  await expect(page.getByRole('link', { name: /CVE Explorer/ })).toBeVisible();
});
