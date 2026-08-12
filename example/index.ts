import Fastify from 'fastify'
import fastifyAwsSigV4 from '../src/index.ts';

const ACCESS_KEY_ID = "hello";
const SECRET_ACCESS_KEY = "world";
const REGION = "ukraine-kiev";
const SERVICE = "my-service";

const fastify = Fastify();

fastify.get('/', async function handler (request, reply) {
  return "Send signed POST or GET to /protected";
})

await fastify.register(fastifyAwsSigV4, {
  region: REGION,
  service: SERVICE,

  // Check whether this works for you:
  // skipCaptureRawBody: true,

  async getCredentials(accessKeyId: string) {
    if (accessKeyId !== ACCESS_KEY_ID) {
      return null;
    }

    return {
      accessKeyId,
      secretAccessKey: SECRET_ACCESS_KEY
    };
  },
});

fastify.addHook("preHandler", fastify.verifyAwsSigV4);

fastify.post(
  "/protected",

  async request => {
    console.log(`Successfully executed POST as ${request.accessKeyId}`);

    return {
      ok: true,
      body: request.body
    };
  }
);

fastify.get(
  "/protected",

  async request => {
    console.log(`Successfully executed GET as ${request.accessKeyId}`);

    return {
      ok: true
    };
  }
);

const listenAddress = await fastify.listen();

console.log(`\n\nServer listening on ${listenAddress}. Try sending a signed GET or POST to /protected. Use the following credentials:\n`);
console.log(`      accessKeyId: ${ACCESS_KEY_ID}`);
console.log(`  secretAccessKey: ${SECRET_ACCESS_KEY}`);
console.log(`           region: ${REGION}`);
console.log(`          service: ${SERVICE}`);
console.log();
