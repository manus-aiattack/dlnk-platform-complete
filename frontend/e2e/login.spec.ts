import { test, expect } from '@playwright/test';

test.describe('Login Flow', () => {
  test('should display login page', async ({ page }) => {
    await page.goto('/');
    
    await expect(page.getByText('dLNk Attack Platform')).toBeVisible();
    await expect(page.getByPlaceholder('Enter username')).toBeVisible();
    await expect(page.getByPlaceholder('Enter password')).toBeVisible();
    await expect(page.getByRole('button', { name: /login/i })).toBeVisible();
  });

  test('should show error on invalid credentials', async ({ page }) => {
    await page.goto('/');
    
    await page.getByPlaceholder('Enter username').fill('wronguser');
    await page.getByPlaceholder('Enter password').fill('wrongpass');
    await page.getByRole('button', { name: /login/i }).click();
    
    await expect(page.getByText(/invalid credentials/i)).toBeVisible();
  });

  test('should navigate to dashboard on successful login', async ({ page }) => {
    // Mock API response
    await page.route('**/auth/login', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ token: 'test-token-123' }),
      });
    });

    await page.goto('/');
    
    await page.getByPlaceholder('Enter username').fill('admin');
    await page.getByPlaceholder('Enter password').fill('password');
    await page.getByRole('button', { name: /login/i }).click();
    
    await expect(page.getByText('Attack Dashboard')).toBeVisible();
  });
});

