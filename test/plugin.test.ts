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

function signedRequest(
  payload: string,
  extraHeaders: Record<string, string> = {},
  includePayloadHash = true,
  host = "example.test",
  method = "POST",
  path = "/protected?source=test",
): SignedRequest {
  const payloadHash = crypto.createHash("sha256").update(payload).digest("hex");

  const headers: Record<string, string> = {
    Host: host,
    "Content-Type": "application/json",
    "X-Amz-Date": requestTimeInAmzDate
  };

  if (includePayloadHash) headers["X-Amz-Content-Sha256"] = payloadHash;

  Object.assign(headers, extraHeaders);

  const request: aws4.Request = {
    host,
    method,
    path,
    body: payload,
    headers,
    doNotModifyHeaders: true,
    region: "eu-west-1",
    service: "execute-api",
  };

  const signer = new aws4.RequestSigner(request, credentials);
  signer.datetime = requestTimeInAmzDate;
  signer.sign();

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

test("accepts a valid request within the allowed clock skew", async t => {
  const app = await createApp({
    now: () => new Date("1991-08-24T12:00:30.000Z"),
  });
  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}');
  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 200);
});

test("rejects a credential scope date that differs from X-Amz-Date", async t => {
  const app = await createApp();
  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}');
  request.headers.Authorization = request.headers.Authorization.replace(
    "/19910824/eu-west-1/execute-api/aws4_request",
    "/19910825/eu-west-1/execute-api/aws4_request",
  );

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 401);
});

test("sets request.accessKeyId after successful signature verification", async t => {
  const app = await createApp();
  t.after(() => app.close());

  app.get("/identity", { preValidation: app.verifyAwsSigV4 }, async request => ({
    accessKeyId: request.accessKeyId,
  }));

  const request = signedRequest("", {}, true, "example.test", "GET", "/identity");
  const response = await app.inject({
    method: "GET",
    url: request.url,
    headers: request.headers,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { accessKeyId: credentials.accessKeyId });
});

test("accepts a signed request with a body sent through fetch over HTTP", async t => {
  const app = await createApp();
  t.after(() => app.close());

  const address = await app.listen({ port: 0, host: "127.0.0.1" });
  const host = new URL(address).host;
  const request = signedRequest('{"hello":"fetch"}', {}, true, host);

  // fetch supplies these transport-managed headers itself. They must not be signed.
  delete request.headers.Host;
  delete request.headers["Content-Length"];

  const response = await fetch(`${address}${request.url}`, {
    method: "POST",
    headers: request.headers,
    body: request.payload,
  });

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { body: { hello: "fetch" } });
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

test("rejects a request without X-Amz-Content-Sha256 in case body is not captured", async t => {
  const app = await createApp({
    skipCaptureRawBody: true
  });
  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}', {}, false);

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 401);
});

test("verifies a request without X-Amz-Content-Sha256 when capturing raw bodies", async t => {
  const app = await createApp({ skipCaptureRawBody: false });
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

  const request = signedRequest('{}', {
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

test("returns custom unauthorized response body", async t => {
  const app = Fastify();

  const customUnauthorizedResponseBody = { message: "Custom Unauthorized" };

  await app.register(fastifyAwsSigV4, {
    region: "eu-west-1",
    service: "execute-api",
    getCredentials: () => credentials,
    now: () => requestTime,
    unauthorizedResponseBody: customUnauthorizedResponseBody
  });

  app.get("/protected", { preValidation: app.verifyAwsSigV4 }, async () => ({ ok: true }));

  t.after(() => app.close());

  const request = signedRequest('{}', {
    "X-Amz-Content-Sha256": "wrong",
  });

  const response = await app.inject({
    method: "GET",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.json(), customUnauthorizedResponseBody);
});

test("rejects unsupported temporary credentials", async t => {
  const sessionCredentials = { ...credentials, sessionToken: "temporary-session-token" };
  const app = await createApp({
    getCredentials: () => sessionCredentials,
  });
  t.after(() => app.close());
  const request = signedRequest('{"hello":"world"}');

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

test("does not retain the raw request body without fastify-raw-body", async t => {
  const app = Fastify();

  await app.register(fastifyAwsSigV4, {
    region: "eu-west-1",
    service: "execute-api",
    getCredentials: () => credentials,
    now: () => requestTime,
  });

  app.post("/protected", { preValidation: app.verifyAwsSigV4 }, async request => {
    const rawBody = (request as typeof request & { rawBody?: unknown }).rawBody;
    return {
      body: request.body,
      rawBody: Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : null,
    };
  });

  t.after(() => app.close());

  const request = signedRequest('{"hello":"world"}');

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload: request.payload,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { body: { hello: "world" }, rawBody: null });
});

test("rejects a DELETE body that was not included in the signature", async t => {
  const app = Fastify();

  await app.register(fastifyAwsSigV4, {
    region: "eu-west-1",
    service: "execute-api",
    getCredentials: () => credentials,
    now: () => requestTime,
  });

  app.delete("/protected", { preValidation: app.verifyAwsSigV4 }, async request => ({ body: request.body }));
  t.after(() => app.close());

  const unsignedBodyRequest: aws4.Request = {
    host: "example.test",
    method: "DELETE",
    path: "/protected",
    headers: {
      Host: "example.test",
      "Content-Type": "application/json",
      "X-Amz-Date": requestTimeInAmzDate,
    },
    doNotModifyHeaders: true,
    region: "eu-west-1",
    service: "execute-api",
  };
  aws4.sign(unsignedBodyRequest, credentials);

  const response = await app.inject({
    method: "DELETE",
    url: "/protected",
    headers: unsignedBodyRequest.headers as Record<string, string>,
    payload: '{"admin":true}',
  });

  assert.equal(response.statusCode, 401);
});

test("preserves Fastify body limits", async t => {
  const app = Fastify({ bodyLimit: 8 });

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

  assert.equal(response.statusCode, 413);
  assert.equal(response.json().code, "FST_ERR_CTP_BODY_TOO_LARGE");
});

test("does not interfere with fastify-raw-body", async t => {
  const app = await createApp();
  t.after(() => app.close());

  app.post("/raw-body", {
    config: { rawBody: true },
    preValidation: app.verifyAwsSigV4,
  }, async request => {
    const rawBody = (request as typeof request & { rawBody?: unknown }).rawBody;
    return { rawBody: Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : null };
  });

  const payload = '{"hello":"compatibility"}';
  const request = signedRequest(payload, {}, true, "example.test", "POST", "/raw-body");

  const response = await app.inject({
    method: "POST",
    url: request.url,
    headers: request.headers,
    payload,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { rawBody: payload });
});
