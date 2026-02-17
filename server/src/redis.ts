import { createClient, RedisClientType } from "redis";
import { config } from "./config";

let client: RedisClientType | null = null;
let connectingPromise: Promise<RedisClientType | null> | null = null;

const createRedisClient = (): RedisClientType => {
  return createClient({
    socket: {
      host: config.redis.host,
      port: config.redis.port,
      connectTimeout: 2000,
      reconnectStrategy: (retries) => {
        if (retries > 10) {
          return new Error("Redis reconnect retry limit exceeded");
        }

        return Math.min(retries * 200, 2000);
      }
    },
    password: config.redis.password,
    database: config.redis.db
  });
};

export const getRedisClient = async (): Promise<RedisClientType | null> => {
  if (!config.redis.enabled) {
    return null;
  }

  if (client?.isOpen) {
    return client;
  }

  if (connectingPromise) {
    return connectingPromise;
  }

  client = createRedisClient();
  client.on("error", (error) => {
    console.error("[redis] client error", error);
  });

  connectingPromise = client
    .connect()
    .then(() => client)
    .catch((error) => {
      console.error("[redis] connection failed, continuing without distributed limits", error);
      return null;
    })
    .finally(() => {
      connectingPromise = null;
    });

  const connected = await connectingPromise;
  if (!connected) {
    client = null;
  }

  return connected;
};

export const closeRedis = async (): Promise<void> => {
  if (!client) {
    return;
  }

  try {
    if (client.isOpen) {
      await client.quit();
    }
  } catch {
    try {
      client.disconnect();
    } catch {
      // noop
    }
  } finally {
    client = null;
    connectingPromise = null;
  }
};
