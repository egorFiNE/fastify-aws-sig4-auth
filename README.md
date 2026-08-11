# fastify-aws-sig4-auth

Fastify plugin that verifies AWS Signature Version 4 on requests.

Use this to protect your API routes with the battle-tested and widely supported AWS signature algorithm.

You can use your favorite tool such as Postman to send signed requests for your app. In fact, this module has been primarily created to sign and call private APIs from Postman.

The only runtime dependency is [mhart's excellent aws4 module](https://github.com/mhart/aws4).

## Install

```sh
npm install fastify-aws-sig4-auth
```

## Usage

### Basic server-side syntax

```ts
import Fastify from "fastify";
import fastifyAwsSigV4 from "fastify-aws-sig4-auth";

const app = Fastify();

await app.register(fastifyAwsSigV4, {
  // Any string value will do, but you will have to supply the same
  // values to craft valid signature.
  region: "ukraine-kiev",
  service: "my-service",

  async getCredentials(accessKeyId) {
    // Actually query the database for your user
    return {
      accessKeyId,
      secretAccessKey: 'secret-access-key'
    };

    // In case the user is unknown:
    // return null;
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
    console.log(`Successfully authenticated with ${request.accessKeyId}`);

    return {
      ok: true
    };
  }
);

// Example 2, handle all routes:
app.addHook("preHandler", app.verifyAwsSigV4);
```

The plugin captures received bytes (raw body) for SigV4-authorized requests before Fastify parses the body. It is compatible with `fastify-raw-body`: if the application already uses it, its `request.rawBody` behavior is unchanged.

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

// Now send as usual:
const response = await fetch(request);
if (!response.ok) throw new Error(`Request failed: ${response.status}`);
console.log(await response.json());
```

The body passed to `fetch()` must be exactly the body that was signed, so absolutely do `JSON.stringify()` just once.

### CORS considerations

Configure CORS to allow `Authorization`, `Content-Type`, `X-Amz-Date` and `X-Amz-Content-Sha256` when calling a different origin. Use `@fastify/cors`.

## Options

| Option | Required | Description |
| --- | --- | --- |
| `region` | Yes | Region required in the SigV4 credential scope |
| `service` | Yes | Service required in the SigV4 credential scope |
| `getCredentials(accessKeyId, request)` | Yes | Returns credentials for an enabled access key, or `null` when unknown. It may be async. |
| `maxClockSkewMs` | No | Allowed clock difference from `X-Amz-Date`; defaults to a minute. |
| `unauthorizedResponseBody` | No | What should we `reply.send()` in case we are serving a `401` response. Default: `{ message: "Unauthorized" }` |

Temporary AWS credentials are deliberately not supported.

## `request` properties

`request.accessKeyId` is populated in case of successful authentication.

## Request requirements

Protected requests must use `AWS4-HMAC-SHA256` and include:

- `Authorization` with a SigV4 credential, signed-header list, and signature
- `Host` in the signed-header list
- `X-Amz-Date` matching the credential date scope
- Optional `X-Amz-Content-Sha256` containing the hexadecimal SHA-256 hash of the request body. If omitted, the payload is still covered by the recomputed signature.

The plugin responds with `401 { "message": "Unauthorized" }` for invalid signatures, unknown keys, invalid payload hashes, malformed headers, and timestamps outside the configured skew. Credential-lookup failures produce `500` and are logged.

`UNSIGNED-PAYLOAD` intentionally rejected. AWS streaming payload signatures (`STREAMING-AWS4-HMAC-SHA256-*`) are not supported.

## Development

```sh
npm install
npm run check
npm test
npm run build
```

The package is ESM-only.

### eslint

You will need to install `eslint-config-airbnb-extended`, then force install `typescript@6`, `@eslint/js` and `eslint@latest`. Then run:

```sh
npx eslint src
```
