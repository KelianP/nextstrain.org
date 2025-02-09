/**
 * Redis is used for storing user sessions (see ./authn/index.js) and user
 * staleness timestamps (see ./user.js).
 *
 * The production Redis instance is configured for both volatile (expiring) and
 * non-volatile data using the "volatile-ttl" eviction policy.  User sessions
 * are volatile (but often long-lived) and have a rolling expiration identical
 * to the session cookie's.  Staleness timestamps are volatile with a short
 * TTL.
 *
 * If you're storing more data in Redis, note that keys will default to
 * non-volatile unless an expiration is set.
 *
 * @module redis
 * @see module:authn
 * @see module:user
 * @see https://redis.io/docs/manual/eviction/
 */

const Redis = require("ioredis");
const utils = require("./utils");


/**
 * Global Redis client/connection shared by the app.
 *
 * Connection is made at app start if `REDIS_URL` is defined in the
 * environment, such as in our Heroku deployments.  Otherwise remains null.
 */
const REDIS = process.env.REDIS_URL
  ? herokuRedisClient(process.env.REDIS_URL)
  : null;


function herokuRedisClient(urlStr) {
  const url = new URL(urlStr);

  // Heroku Redis' TLS socket is documented to be on the next port up.  The
  // scheme for secure redis:// URLs is rediss://.
  if (url.protocol === "redis:") {
    utils.verbose(`Rewriting Redis URL <${scrubUrl(url)}> to use TLS`);
    url.protocol = "rediss:";
    url.port = Number(url.port) + 1;
  }

  const client = new Redis(url.toString(), {
    tls: {
      // It is pretty frustrating that Heroku doesn't provide verifiable
      // certs.  Although we're not using the Heroku Redis buildpack, the
      // issue is documented here nicely
      // <https://github.com/heroku/heroku-buildpack-redis/issues/15>.
      rejectUnauthorized: false
    }
  });

  client.scrubbedUrl = scrubUrl(url);

  return client;
}


function scrubUrl(url) {
  const scrubbedUrl = new URL(url);
  scrubbedUrl.password = "XXXXXX";
  return scrubbedUrl;
}


module.exports = {
  REDIS,
};
