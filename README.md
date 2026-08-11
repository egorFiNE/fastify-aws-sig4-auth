# fastify-aws-sig4-auth

Fastify plugin that verifies AWS Signature Version 4 on requests.

Use this to protect your API routes with battle-tested AWS signature algorithm. You can use your favorite tool such as Postman to generate and sign requests for your app. In fact, this module has been primarily created to sign and call private APIs from Postman.

The only dependencies are [mhart's excellent aws4 module](https://github.com/mhart/aws4) and [fastify-raw-body](https://github.com/Eomm/fastify-raw-body) (although you can substitute the latter with your own implementation).

## Install

```sh
npm install fastify-raw-body fastify-aws-sig4-auth
```

## Usage

### Protect only GET routes

```ts
import Fastify from "fastify";
import fastifyAwsSigV4 from "fastify-aws-sig4-auth";

const app = Fastify();

await app.register(fastifyAwsSigV4, {
  region: "ukraine-kiev",
  service: "my-service",
  async getCredentials(accessKeyId) {
    // Actually query the database for your user
    return {
      accessKeyId,
      secretAccessKey: 'secret-access-key'
    };
  },
});

// Now the fastify instance is ready to do the auth.

// Example 1, handle a single route:
app.post(
  "/private",
  {
    preValidation: app.verifyAwsSigV4
  },

  async request => {
    return { ok: true, body: request.body };
  }
);

// Example 2, handle all routes:
app.addHook("preHandler", instance.verifyAwsSigV4);
```

### Protect routes with bodies (POST, PUT, PATCH)

```ts
import Fastify from "fastify";
import fastifyRawBody from "fastify-raw-body";
import fastifyAwsSigV4 from "fastify-aws-sig4-auth";

const app = Fastify();

// This is done according to fastify-raw-body documentation
await app.register(fastifyRawBody, {
  encoding: false,
  global: false,
  runFirst: true
});

await app.register(fastifyAwsSigV4, {
  region: "ukraine-kiev",
  service: "my-service",
  async getCredentials(accessKeyId) {
    // Actually query the database for your user
    return {
      accessKeyId,
      secretAccessKey: 'secret-access-key'
    };
  },
});

// Now the fastify instance is ready to do the auth.

// Example 1, handle a single route:
app.post(
  "/private",
  {
    // Again: this is according to fastify-raw-body docs
    config: {
      rawBody: true
    },

    preValidation: app.verifyAwsSigV4
  },

  async request => {
    return { ok: true, body: request.body };
  }
);

// Example 2, handle all routes:
app.addHook("preHandler", instance.verifyAwsSigV4);
```

Register `fastify-raw-body` before defining protected routes, with `encoding: false` so `request.rawBody` is a `Buffer`. The `global: false` plus per-route `config.rawBody: true` setup avoids retaining duplicate body data for unprotected routes. `runFirst: true` captures bytes before another `preParsing` hook can alter them.

If `request.rawBody` is absent or not a `Buffer`, this plugin returns `500 { "message": "Internal Server Error" }` and logs the configuration error. It does not silently verify an empty body.

### Call a protected route with `fetch()`

Sign the request before sending it. [`aws4fetch`](https://github.com/mhart/aws4fetch) by the same author as `aws4`, creates a standard signed `Request`; the network call below is the native `fetch()`:

```sh
npm install aws4fetch
```

```ts
import { AwsClient } from "aws4fetch";

const body = JSON.stringify({ hello: "world" });

const client = new AwsClient({
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  // Must match the plugin configuration:
  region: "ukraine-kiev",
  service: "my-service"
});

const request = await client.sign("http://localhost:3000/private", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body
});

const response = await fetch(request);
if (!response.ok) throw new Error(`Request failed: ${response.status}`);

console.log(await response.json());
```

The body passed to `fetch()` must be exactly the body that was signed. Do not set or sign `Host` or `Content-Length`; `fetch()` manages them.

### CORS considerations

Configure CORS to allow `Authorization`, `Content-Type`, and `X-Amz-Date` when calling a different origin. Use `@fastify/cors`.

## Options

| Option | Required | Description |
| --- | --- | --- |
| `region` | Yes | Region required in the SigV4 credential scope |
| `service` | Yes | Service required in the SigV4 credential scope |
| `getCredentials(accessKeyId, request)` | Yes | Returns credentials for an enabled access key, or `null` when unknown. It may be async. |
| `maxClockSkewMs` | No | Allowed clock difference from `X-Amz-Date`; defaults to a minute. |
| `unauthorizedResponseBody` | No | What should we `reply.send()` in case we are serving a `401` response. Default: `{ message: "Unauthorized" }` |

Temporary AWS credentials are deliberately not supported.

## Request requirements

Protected requests must use `AWS4-HMAC-SHA256` and include:

- `Authorization` with a SigV4 credential, signed-header list, and signature
- `Host` in the signed-header list
- `X-Amz-Date` matching the credential date scope
- Optional `X-Amz-Content-Sha256` containing the hexadecimal SHA-256 hash of the request body. If omitted, the payload is still covered by the recomputed signature.

The plugin responds with `401 { "message": "Unauthorized" }` for invalid signatures, unknown keys, invalid payload hashes, malformed headers, and timestamps outside the configured skew. Credential-lookup failures produce `500` and are logged.

`UNSIGNED-PAYLOAD` is intentionally rejected unless `allowUnsignedPayload` is enabled. AWS streaming payload signatures (`STREAMING-AWS4-HMAC-SHA256-*`) are not supported.

## Development

```sh
npm install
npm run check
npm test
npm run build
```

The package is ESM-only.
