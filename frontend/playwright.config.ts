import { defineConfig } from '@playwright/test';
export default defineConfig({ webServer: { command: 'npm run dev', url: 'http://127.0.0.1:3000', reuseExistingServer: true }, use: { baseURL: 'http://127.0.0.1:3000' } });
