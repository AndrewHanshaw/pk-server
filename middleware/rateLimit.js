const expressRateLimit = require('express-rate-limit');
const { Ratelimit } = require('@upstash/ratelimit');
const { Redis } = require('@upstash/redis');

// Rate limiting for POST /sign.

// When Upstash Redis credentials are present, counters live in Redis so every serverless instance shares the same view of each client's request count.
// If they are missing (e.g. local development, or a misconfigured deployment) it falls back to an in-memory limiter, which is only accurate within a single process.

function envInt(name, fallback) {
  const value = parseInt(process.env[name], 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function tooManyRequests(req, res) {
  res.status(429).json({ error: 'Too many signing requests, try again later' });
}

// Credentials come from the Vercel Upstash integration.
const redisUrl = process.env.KV_REST_API_URL;
const redisToken = process.env.KV_REST_API_TOKEN;
const redis = redisUrl && redisToken ? new Redis({ url: redisUrl, token: redisToken }) : null;

if (!redis) {
  console.warn('Rate limiting: Upstash Redis not configured, using per-instance in-memory store');
}

function createLimiter({ name, windowMs, max }) {
  if (!redis) {
    return expressRateLimit({
      windowMs,
      limit: max,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      handler: tooManyRequests,
    });
  }

  const limiter = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(max, `${windowMs} ms`),
    prefix: `pk-server:ratelimit:${name}`,
  });

  return async function (req, res, next) {
    try {
      const { success, reset } = await limiter.limit(req.ip);
      if (!success) {
        res.set('Retry-After', String(Math.max(1, Math.ceil((reset - Date.now()) / 1000))));
        return tooManyRequests(req, res);
      }
    } catch (err) {
      // Fail open: a Redis outage shouldn't take the signing endpoint down.
      console.error('Rate limiter error, allowing request:', err);
    }
    next();
  };
}

const signBurstLimiter = createLimiter({
  name: 'burst',
  windowMs: envInt('RATE_LIMIT_BURST_WINDOW_MS', 60 * 1000),
  max: envInt('RATE_LIMIT_BURST_MAX', 5),
});

const signHourlyLimiter = createLimiter({
  name: 'hourly',
  windowMs: envInt('RATE_LIMIT_HOURLY_WINDOW_MS', 60 * 60 * 1000),
  max: envInt('RATE_LIMIT_HOURLY_MAX', 40),
});

module.exports = { signBurstLimiter, signHourlyLimiter };
