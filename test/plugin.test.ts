import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import aws4 from "aws4";
import Fastify from "fastify";
import fastifyRawBody from "fastify-raw-body";
import fastifyAwsSigV4, { type AwsSigV4PluginOptions } from "../src/index.js";

const credentials = {
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
};

// Magic date for tests
const requestTime = new Date("1991-08-24T12:00:00.000Z");
const requestTimeInAmzDate = '19910824T120000Z';
const requestTimeInAmzDateOneHourEarlier = '19910824T110000Z'; // 1 hour earlier than requestTime

async function createApp(overrides: Partial<AwsSigV4PluginOptions> = {}) {
  const app = Fastify();

  await app.register(fastifyRawBody, {
    encoding: false,
    global: false,
    runFirst: true
  });

  await app.register(fastifyAwsSigV4, {
    region: "eu-west-1",
    service: "execute-api",
    getCredentials: (accessKeyId) => accessKeyId === credentials.accessKeyId ? credentials : null,
    now: () => requestTime,
    ...overrides
  });

  app.post("/protected", {
    config: { rawBody: true },
    preValidation: app.verifyAwsSigV4,
  }, async (request) => ({ body: request.body }));

  return app;
}

type SignedRequest = {
  headers: Record<string, string>;
  payload: string;
  url: string;
};

function signedRequest(payload: string, extraHeaders: Record<string, string> = {}, includePayloadHash = true): SignedRequest {
  const payloadHash = crypto.createHash("sha256").update(payload).digest("hex");

  const host = "example.test";

  const headers: Record<string, string> = {
    Host: host,
    "Content-Type": "application/json",
    "X-Amz-Date": requestTimeInAmzDate
  };

  if (includePayloadHash) headers["X-Amz-Content-Sha256"] = payloadHash;

  Object.assign(headers, extraHeaders);

  const request: aws4.Request = {
    host,
    method: "POST",
    path: "/protected?source=test",
    body: payload,
    headers,
    region: "eu-west-1",
    service: "execute-api",
  };

  aws4.sign(request, credentials);

  return {
    headers: request.headers as Record<string, string>,
    payload,
    url: request.path!
  };
}

test("accepts a correctly signed request and preserves its parsed payload", async t => {
  const app = await createApp();
  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}');

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { body: { hello: "world" } });
});

test("rejects a body that differs from the signed payload", async t => {
  const app = await createApp();
  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}');

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: '{"hello":"there"}',
  });

  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.json(), { message: "Unauthorized" });
});

test("verifies a request without X-Amz-Content-Sha256", async t => {
  const app = await createApp();
  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}', {}, false);

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 200);
});

test("rejects an expired signature", async t => {
  const app = await createApp();
  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}');
  request.headers["X-Amz-Date"] = requestTimeInAmzDateOneHourEarlier;

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 401);
});

test("rejects UNSIGNED-PAYLOAD by default", async t => {
  const app = await createApp();
  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}', {
    "X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD",
  });

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 401);
});

// test("requires the configured session token for temporary credentials", async t => {
//   const sessionCredentials = { ...credentials, sessionToken: "temporary-session-token" };
//   const app = await createApp({
//     getCredentials: () => sessionCredentials,
//   });
//   t.after(() => app.close());
//   const request = signedRequest('{"hello":"world"}');

//   const response = await app.inject({
//     method: "POST",
//     url: request.url,
//     headers: request.headers,
//     payload: request.payload,
//   });

//   assert.equal(response.statusCode, 401);
// });

test("fails clearly when the application does not provide a raw request body", async t => {
  const app = Fastify();

  await app.register(fastifyAwsSigV4, {
    region: "eu-west-1",
    service: "execute-api",
    getCredentials: () => credentials,
    now: () => requestTime,
  });

  app.post("/protected", { preValidation: app.verifyAwsSigV4 }, async () => ({ ok: true }));

  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}');

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 500);
  assert.deepEqual(response.json(), { message: "Internal Server Error" });
});
