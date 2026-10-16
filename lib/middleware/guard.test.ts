import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';

import guard from '@/middleware/guard';

process.env.NODE_NAME = 'mock';

const GUARD_ENVS = ['GUARD_ENABLE', 'GUARD_RATE_LIMIT', 'GUARD_RATE_LIMIT_WINDOW', 'GUARD_ALLOW_IPS', 'GUARD_BLOCK_IPS', 'GUARD_TRUSTED_PROXIES'];

const peer = (remoteAddress: string) => ({ incoming: { socket: { remoteAddress } } });

const setup = async (envs: Record<string, string> = {}) => {
    Object.assign(process.env, { GUARD_ENABLE: '1', ...envs });
    vi.resetModules();
    return (await import('@/app')).default;
};

afterEach(() => {
    for (const name of GUARD_ENVS) {
        delete process.env[name];
    }
    vi.doUnmock('@guardcore/hono');
    vi.resetModules();
});

describe('guard', () => {
    it('is off by default and does not load the package', async () => {
        const loaded = vi.fn(() => ({}));
        vi.doMock('@guardcore/hono', loaded);
        vi.resetModules();
        const app = (await import('@/app')).default;
        const responses = await Promise.all([1, 2, 3].map(() => app.request('/test/1', {}, peer('203.0.113.1'))));
        expect(responses.map((response) => response.status)).toEqual([200, 200, 200]);
        expect(loaded).not.toHaveBeenCalled();
    });

    it('returns 429 after the configured limit and keeps the normal headers', async () => {
        const app = await setup({ GUARD_RATE_LIMIT: '2' });
        expect((await app.request('/test/1', {}, peer('203.0.113.2'))).status).toBe(200);
        expect((await app.request('/test/1', {}, peer('203.0.113.2'))).status).toBe(200);
        const blocked = await app.request('/test/1', {}, peer('203.0.113.2'));
        expect(blocked.status).toBe(429);
        expect(blocked.headers.get('access-control-allow-methods')).toBe('GET');
        expect(blocked.headers.get('rsshub-node')).toBe('mock');
        expect(blocked.headers.get('cache-control')).toBe('no-store');
        expect(blocked.headers.get('strict-transport-security')).toBeNull();
        expect((await app.request('/test/1', {}, peer('203.0.113.3'))).status).toBe(200);
    });

    it('leaves successful responses unchanged', async () => {
        const app = await setup();
        const response = await app.request('/test/1', {}, peer('203.0.113.4'));
        expect(response.status).toBe(200);
        expect(response.headers.get('content-type')).toBe('application/xml; charset=utf-8');
        expect(response.headers.get('cache-control')).toMatch(/^public, max-age=/);
        expect(response.headers.get('strict-transport-security')).toBeNull();
        expect(response.headers.get('x-frame-options')).toBeNull();
    });

    it('rejects addresses outside the allow list', async () => {
        const app = await setup({ GUARD_ALLOW_IPS: '198.51.100.0/24' });
        expect((await app.request('/test/1', {}, peer('198.51.100.7'))).status).toBe(200);
        expect((await app.request('/test/1', {}, peer('203.0.113.5'))).status).toBe(403);
    });

    it('rejects addresses on the block list', async () => {
        const app = await setup({ GUARD_BLOCK_IPS: '203.0.113.6, 192.0.2.0/24' });
        expect((await app.request('/test/1', {}, peer('203.0.113.6'))).status).toBe(403);
        expect((await app.request('/test/1', {}, peer('192.0.2.9'))).status).toBe(403);
        expect((await app.request('/test/1', {}, peer('203.0.113.7'))).status).toBe(200);
    });

    it('ignores X-Forwarded-For from a peer that is not a trusted proxy', async () => {
        const app = await setup({ GUARD_RATE_LIMIT: '2', GUARD_BLOCK_IPS: '192.0.2.99' });
        const spoof = (client: string) => app.request('/test/1', { headers: { 'X-Forwarded-For': client } }, peer('203.0.113.8'));
        expect((await spoof('192.0.2.10')).status).toBe(200);
        expect((await spoof('192.0.2.11')).status).toBe(200);
        expect((await spoof('192.0.2.12')).status).toBe(429);
        expect((await app.request('/test/1', { headers: { 'X-Forwarded-For': '192.0.2.99' } }, peer('203.0.113.9'))).status).toBe(200);
    });

    it('honors X-Forwarded-For from a trusted proxy', async () => {
        const app = await setup({ GUARD_RATE_LIMIT: '2', GUARD_TRUSTED_PROXIES: '10.0.0.0/8', GUARD_BLOCK_IPS: '192.0.2.99' });
        const via = (client: string) => app.request('/test/1', { headers: { 'X-Forwarded-For': client } }, peer('10.0.0.1'));
        expect((await via('198.51.100.1')).status).toBe(200);
        expect((await via('198.51.100.1')).status).toBe(200);
        expect((await via('198.51.100.1')).status).toBe(429);
        expect((await via('198.51.100.2')).status).toBe(200);
        expect((await via('192.0.2.99')).status).toBe(403);
    });

    it('matches IPv4 trusted proxies against IPv4-mapped peer addresses', async () => {
        const app = await setup({ GUARD_RATE_LIMIT: '1', GUARD_TRUSTED_PROXIES: '10.0.0.0/8' });
        const via = (client: string) => app.request('/test/1', { headers: { 'X-Forwarded-For': client } }, peer('::ffff:10.0.0.1'));
        expect((await via('198.51.100.20')).status).toBe(200);
        expect((await via('198.51.100.21')).status).toBe(200);
        expect((await via('198.51.100.20')).status).toBe(429);
    });

    it('blocks an attack pattern in the query', async () => {
        const app = await setup();
        const response = await app.request('/test/1?q=' + encodeURIComponent('<script>alert(1)</script>'), {}, peer('203.0.113.10'));
        expect([400, 403]).toContain(response.status);
    });

    it('does not block a localhost or LAN Referer', async () => {
        const app = await setup();
        const statuses = await Promise.all(
            ['http://localhost:1200/', 'http://127.0.0.1:1200/', 'http://192.168.1.20:1200/'].map(async (referer, index) => (await app.request('/test/1', { headers: { Referer: referer } }, peer(`203.0.113.${20 + index}`))).status)
        );
        expect(statuses).toEqual([200, 200, 200]);
    });

    it('blocks an attack pattern in the Referer', async () => {
        const app = await setup();
        const response = await app.request('/test/1', { headers: { Referer: 'http://example.com/?q=<script>alert(1)</script>' } }, peer('203.0.113.23'));
        expect([400, 403]).toContain(response.status);
    });

    it('does not block a route path that carries a URL parameter', async () => {
        const app = await setup();
        const url = encodeURIComponent('https://example.com/news/中文?id=1&page=2');
        const response = await app.request(`/test/1/${url}`, {}, peer('203.0.113.11'));
        expect(response.status).toBe(200);
        expect((await app.request('/test/changelog/README.md', {}, peer('203.0.113.11'))).status).toBe(200);
    });

    it('does not scan request bodies', async () => {
        const app = new Hono();
        app.use(guard);
        app.post('/echo', async (ctx) => ctx.text(String((await ctx.req.text()).length)));
        const body = "<script>alert(1)</script>' OR 1=1 --";
        const response = await app.request('/echo', { method: 'POST', body }, peer('203.0.113.12'));
        expect(response.status).toBe(200);
        expect(await response.text()).toBe(String(body.length));
    });
});
