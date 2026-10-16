import type { MiddlewareHandler } from 'hono';

import { config } from '@/config';
import logger from '@/utils/logger';

// Every detection category except 'recon' (its path probes match route segments such as /changelog, /language, README.md and .shtml) and 'ssrf' (browsers send the page address as Referer, and guard-core 4.4.0 flags localhost and LAN addresses in it).
const detectionCategories = [
    'cmd_injection',
    'cms_probing',
    'code_injection',
    'deserialization',
    'dir_traversal',
    'file_inclusion',
    'file_upload',
    'http_split',
    'ldap',
    'nosql',
    'path_traversal',
    'proto_pollution',
    'sensitive_file',
    'sqli',
    'template',
    'xml',
    'xss',
];

let guard: Promise<MiddlewareHandler> | undefined;

const create = async () => {
    // Loaded on first use so the package is never imported while GUARD_ENABLE is off.
    const { createGuardMiddleware, resolveHonoClientAddress } = await import('@guardcore/hono');
    return createGuardMiddleware({
        // A dual-stack listener reports IPv4 peers as ::ffff:a.b.c.d, which would never match an IPv4 trusted proxy entry.
        connectingIpResolver: (ctx) => resolveHonoClientAddress(ctx)?.replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, '$1'),
        config: {
            logger,
            enableRedis: false,
            enableCors: false,
            securityHeaders: { enabled: false },
            detectionScanBody: false,
            enabledDetectionCategories: detectionCategories,
            rateLimit: config.guard.rateLimit,
            rateLimitWindow: config.guard.rateLimitWindow,
            whitelist: config.guard.allowIps ?? null,
            blacklist: config.guard.blockIps,
            trustedProxies: config.guard.trustedProxies,
        },
    });
};

const middleware: MiddlewareHandler = async (ctx, next) => {
    const response = await (await (guard ??= create()))(ctx, next);
    // A blocked response must not inherit the public Cache-Control set by the header middleware.
    response?.headers.set('Cache-Control', 'no-store');
    return response;
};

export default middleware;
