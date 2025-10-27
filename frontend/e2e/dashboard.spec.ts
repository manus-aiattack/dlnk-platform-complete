import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Mock authentication
    await page.addInitScript(() => {
      localStorage.setItem('auth_token', 'test-token-123');
    });

    // Mock API responses
    await page.route('**/api/stats/dashboard', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          active_attacks: 5,
          total_vulnerabilities: 23,
          success_rate: 87,
          targets_scanned: 42,
          ai_agents_active: 8,
          knowledge_entries: 156,
        }),
      });
    });

    await page.route('**/api/attacks?status=running', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });

    await page.route('**/api/stats/attack-history', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          values: [1, 3, 2, 5, 4, 6, 5],
          labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        }),
      });
    });

    await page.goto('/');
  });

  test('should display dashboard stats', async ({ page }) => {
    await expect(page.getByText('Attack Dashboard')).toBeVisible();
    await expect(page.getByText('Active Attacks')).toBeVisible();
    await expect(page.getByText('Vulnerabilities Found')).toBeVisible();
    await expect(page.getByText('Success Rate')).toBeVisible();
    await expect(page.getByText('Targets Scanned')).toBeVisible();
  });

  test('should show live indicator', async ({ page }) => {
    await expect(page.getByText('Live')).toBeVisible();
  });

  test('should display charts', async ({ page }) => {
    await expect(page.getByText('Attack Timeline')).toBeVisible();
    await expect(page.getByText('Vulnerability Distribution')).toBeVisible();
  });

  test('should navigate to attacks page', async ({ page }) => {
    await page.getByRole('link', { name: 'Attacks' }).click();
    await expect(page.getByText('Attack Manager')).toBeVisible();
  });

  test('should navigate to agents page', async ({ page }) => {
    await page.getByRole('link', { name: 'Agents' }).click();
    await expect(page.getByText('AI Agents')).toBeVisible();
  });
});

