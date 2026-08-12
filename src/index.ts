import crypto from "node:crypto";
import { Transform } from "node:stream";
import aws4 from "aws4";
import fp from "fastify-plugin";
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";

export type AwsSigV4PluginOptions = {
  /** AWS region expected in the credential scope. */
  region: string;

  /** AWS service expected in the credential scope. */
  service: string;

  /**
   * Resolves credentials for the access key from the request Authorization
   * header. Return null when the access key is unknown or disabled.
   */
  getCredentials(
    accessKeyId: string,
    request: FastifyRequest,
  ): Promise<AwsSigV4Credentials | null> | AwsSigV4Credentials | null;

  /** Maximum permitted difference between X-Amz-Date and the current time. */
  maxClockSkewMs?: number;

  /** Response body to send when the request is unauthorized. */
  unauthorizedResponseBody?: any;

  /** Do not capture raw request bytes for signature verification. Defaults to false. */
  skipCaptureRawBody?: boolean;

  /** Provides the current time. For tests only. */
  now?: () => Date;
};

export type AwsSigV4Credentials = {
  accessKeyId: string;
  secretAccessKey: string;
};

declare module "fastify" {
  interface FastifyInstance {
    verifyAwsSigV4: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  interface FastifyRequest {
    accessKeyId: string | null;
  }
}

type ParsedAuthorization = {
  accessKeyId: string;
  date: string;
  region: string;
  service: string;
  signedHeaderNames: string[];
  signature: string;
};

type FastifyPayloadStream = Transform & { receivedEncodedLength: number };

const DEFAULT_401_RESPONSE = { message: "Unauthorized" };
const DEFAULT_MAX_CLOCK_SKEW_MS = 1 * 60 * 1000;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/i;
const EMPTY_PAYLOAD_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const AMZ_DATE_PATTERN = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/;
const AMZ_HMAC_PATTERN = /^AWS4-HMAC-SHA256\s+(.+)$/i;
const DEFAULT_SKIP_CAPTURE_RAW_BODY = false;

const capturedRawBodies = new WeakMap<FastifyRequest, Promise<Buffer>>();
const capturedPayloadHashes = new WeakMap<FastifyRequest, Promise<string>>();

function sendUnauthorized(request: FastifyRequest, reply: FastifyReply, reason: string, unauthorizedResponseBody: any) {
  request.log.debug({ reason }, "AWS SigV4 authentication failed");
  reply.code(401).send(unauthorizedResponseBody);
}

function parseAuthorizationIntoAttributes(authorization: any): Map<string, string> | null {
  if (!authorization) return null;

  // because OutgoingHttpHeader can be supplied here, so we want to make sure we have a string, not an array or something else
  if (typeof authorization !== "string") return null;

  // `authorization` is considered to be a string at this point.

  const match = AMZ_HMAC_PATTERN.exec(authorization);
  if (!match) return null;

  const attributes = new Map<string, string>();
  for (const part of match[1].split(",")) {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex === -1) return null;

    const key = part.slice(0, separatorIndex).trim();
    const value = part.slice(separatorIndex + 1).trim();

    if (!key || !value || attributes.has(key)) return null;

    attributes.set(key, value);
  }

  return attributes;
}

function parseAuthorization(rawAuthorization: any): ParsedAuthorization | null {
  const attributes = parseAuthorizationIntoAttributes(rawAuthorization);
  if (attributes === null) return null;

  const credential = attributes.get("Credential");
  const signedHeaders = attributes.get("SignedHeaders");
  const signature = attributes.get("Signature");
  if (!credential || !signedHeaders || !signature || !SHA256_HEX_PATTERN.test(signature)) return null;

  const credentialParts = credential.split("/");
  if (credentialParts.length !== 5 || credentialParts[4] !== "aws4_request") return null;

  const [ accessKeyId, date, region, service ] = credentialParts;
  if (!accessKeyId || !/^\d{8}$/.test(date) || !region || !service) return null;

  const signedHeaderNames = signedHeaders.split(";");
  if (signedHeaderNames.length === 0 || signedHeaderNames.some(name => !/^[a-z0-9-]+$/.test(name))) return null;

  // We care about the duplicate headers, because those can only be nefarious
  if (new Set(signedHeaderNames).size !== signedHeaderNames.length) return null;

  return { accessKeyId, date, region, service, signedHeaderNames, signature };
}

function parseAmzDate(value: string | null | undefined): number | null {
  if (!value) return null;

  const match = AMZ_DATE_PATTERN.exec(value);
  if (!match) return null;

  const [ , year, month, day, hour, minute, second ] = match;
  const timestamp = Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second)
  );

  const normalizedDate = `${year}-${month}-${day}T${hour}:${minute}:${second}.000Z`;
  return new Date(timestamp).toISOString() === normalizedDate ? timestamp : null;
}

// defensive code, yeah.
function getHeader(request: FastifyRequest, name: string): string | undefined {
  const value = request.headers[name];
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value.join(",") : String(value);
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "hex");
  const rightBuffer = Buffer.from(right, "hex");

  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function hasSigV4Authorization(request: FastifyRequest): boolean {
  const authorization = getHeader(request, "authorization");
  return Boolean(parseAuthorization(authorization));
}

function captureHashAndPossiblyRawBody(request: FastifyRequest, payload: NodeJS.ReadableStream, skipCaptureBody: boolean): FastifyPayloadStream {
  const chunks: Buffer[] = [];
  const bodyLimit = request.routeOptions.bodyLimit;
  let receivedLength = 0;
  const hash = crypto.createHash("sha256");

  const promiseWithResolversForRawBody = Promise.withResolvers<Buffer>();
  if (!skipCaptureBody) capturedRawBodies.set(request, promiseWithResolversForRawBody.promise);

  const promiseWithResolversForHash = Promise.withResolvers<string>();
  capturedPayloadHashes.set(request, promiseWithResolversForHash.promise);

  const capturedPayload = new Transform({
    transform(chunk, encoding, callback) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);

      receivedLength += buffer.length;
      (this as FastifyPayloadStream).receivedEncodedLength += buffer.length;

      if (!skipCaptureBody && receivedLength <= bodyLimit) chunks.push(buffer);

      hash.update(buffer);

      callback(null, chunk);
    },

    flush(callback) {
      if (receivedLength <= bodyLimit) {
        if (!skipCaptureBody) promiseWithResolversForRawBody.resolve(Buffer.concat(chunks));
        promiseWithResolversForHash.resolve(hash.digest("hex"));
      }
      callback();
    }
  }) as FastifyPayloadStream;

  capturedPayload.receivedEncodedLength = 0;

  payload.pipe(capturedPayload);

  return capturedPayload;
}

function createVerifier(options: AwsSigV4PluginOptions) {
  const maxClockSkewMs = options.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
  const now = options.now ?? (() => new Date());
  const unauthorizedResponseBody = options.unauthorizedResponseBody ?? DEFAULT_401_RESPONSE;
  const skipCaptureRawBody = options.skipCaptureRawBody ?? DEFAULT_SKIP_CAPTURE_RAW_BODY;

  if (!Number.isFinite(maxClockSkewMs) || maxClockSkewMs < 0) throw new Error("maxClockSkewMs must be a non-negative finite number");

  return async function verifyAwsSigV4(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const authorization = getHeader(request, "authorization");
    if (!authorization) return sendUnauthorized(request, reply, "Authorization header is missing", unauthorizedResponseBody);

    const parsed = parseAuthorization(authorization);
    if (!parsed) return sendUnauthorized(request, reply, "Authorization header is invalid", unauthorizedResponseBody);
    if (parsed.region !== options.region || parsed.service !== options.service) {
      return sendUnauthorized(request, reply, "Credential scope does not match this verifier", unauthorizedResponseBody);
    }

    const amzDate = getHeader(request, "x-amz-date");
    const timestamp = parseAmzDate(amzDate);
    if (timestamp === null || amzDate === undefined) return sendUnauthorized(request, reply, "X-Amz-Date is invalid", unauthorizedResponseBody);
    if (parsed.date !== amzDate.slice(0, 8)) return sendUnauthorized(request, reply, "Credential date does not match X-Amz-Date", unauthorizedResponseBody);
    if (Math.abs(now().getTime() - timestamp) > maxClockSkewMs) return sendUnauthorized(request, reply, "X-Amz-Date is outside the allowed clock skew", unauthorizedResponseBody);

    if (
      !parsed.signedHeaderNames.includes("host") ||
      !parsed.signedHeaderNames.includes("x-amz-date")
    ) {
      return sendUnauthorized(request, reply, "Required headers are not signed", unauthorizedResponseBody);
    }

    const actualPayloadHashPromise = capturedPayloadHashes.get(request);
    if (!actualPayloadHashPromise) throw new Error("Payload hash was not captured.");
    const actualPayloadHash = await actualPayloadHashPromise;

    const suppliedPayloadHash = getHeader(request, "x-amz-content-sha256");

    if (suppliedPayloadHash) {
      if (skipCaptureRawBody && !parsed.signedHeaderNames.includes("x-amz-content-sha256")) {
        return sendUnauthorized(request, reply, "Required headers are not signed", unauthorizedResponseBody);
      }

      // We have two hashes, so let's compare them
      if (!safeEqual(actualPayloadHash, suppliedPayloadHash)) return sendUnauthorized(request, reply, "Payload hash does not match", unauthorizedResponseBody);

      // hashes do match, all good

    // Without raw bytes, aws4 can only reconstruct an unsigned empty payload.
    } else if (skipCaptureRawBody && actualPayloadHash !== EMPTY_PAYLOAD_SHA256) {
      return sendUnauthorized(request, reply, "Payload hash is missing and skipCaptureRawBody=true", unauthorizedResponseBody);
    }

    const host = getHeader(request, "host");
    if (!host) return sendUnauthorized(request, reply, "Host header is missing", unauthorizedResponseBody);

    const headers: Record<string, string> = {};
    for (const name of parsed.signedHeaderNames) {
      const value = getHeader(request, name);
      if (value === undefined) return sendUnauthorized(request, reply, `Signed header is missing: ${name}`, unauthorizedResponseBody);
      headers[name] = value;
    }

    let credentials: AwsSigV4Credentials | null;
    try {
      credentials = await options.getCredentials(parsed.accessKeyId, request);
    } catch (error) {
      request.log.error({ error }, "AWS SigV4 credential lookup failed");
      return await reply.code(500).send({ message: "Internal Server Error" });
    }

    if (!credentials || credentials.accessKeyId !== parsed.accessKeyId) return sendUnauthorized(request, reply, "Access key is unknown", unauthorizedResponseBody);

    // sessionToken wip?
    // if (credentials.sessionToken && getHeader(request, "x-amz-security-token") !== credentials.sessionToken) {
    //   return sendUnauthorized(request, reply, "Session token does not match");
    // }

    // sessionToken tmp disabled
    if ("sessionToken" in credentials) return sendUnauthorized(request, reply, "Temporary credentials are not supported", unauthorizedResponseBody);

    let rawBody: Buffer | undefined;
    if (!skipCaptureRawBody) {
      const rawBodyPromise = capturedRawBodies.get(request);
      if (!rawBodyPromise) throw new Error("Raw body was not captured.");
      rawBody = await rawBodyPromise;
    }

    const signOptions: aws4.Request = {
      host,
      method: request.method,
      path: request.raw.url ?? request.url,
      headers,
      body: rawBody,
      // Recreate the signature from precisely the received signed headers.
      // fetch() manages Content-Length and browser callers cannot set it.
      doNotModifyHeaders: true,
      region: options.region,
      service: options.service
    };

    // Explicit memory release
    capturedRawBodies.delete(request);
    capturedPayloadHashes.delete(request);

    const signer = new aws4.RequestSigner(signOptions, {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey
      // sessionToken: credentials.sessionToken,
    });
    signer.datetime = amzDate;
    signer.sign();

    const generatedAuthorization = signOptions.headers?.Authorization ?? signOptions.headers?.authorization;
    const expected = parseAuthorization(generatedAuthorization);

    if (!expected) return sendUnauthorized(request, reply, "Did not parse Authorization header", unauthorizedResponseBody);
    if (expected.signedHeaderNames.join(";") !== parsed.signedHeaderNames.join(";")) {
      return sendUnauthorized(request, reply, "Signature headers list does not match", unauthorizedResponseBody);
    }
    if (!safeEqual(parsed.signature, expected.signature)) return sendUnauthorized(request, reply, "Signature does not match", unauthorizedResponseBody);

    // All okay at this point, auth passed
    request.accessKeyId = credentials.accessKeyId;

    return undefined; // make eslint happy
  };
}

const fastifyAwsSigV4: FastifyPluginAsync<AwsSigV4PluginOptions> = async (fastify, options) => {
  fastify.addHook("preParsing", (request, reply, payload, done) => {
    if (!hasSigV4Authorization(request)) return done(null, payload);

    done(null, captureHashAndPossiblyRawBody(request, payload, options.skipCaptureRawBody ?? DEFAULT_SKIP_CAPTURE_RAW_BODY));
  });

  fastify.decorateRequest("accessKeyId", null);
  fastify.decorate("verifyAwsSigV4", createVerifier(options));
};

export default fp(fastifyAwsSigV4, {
  fastify: "5.x",
  name: "fastify-aws-sig4-auth"
});
