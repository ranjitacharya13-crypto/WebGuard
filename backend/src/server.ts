import "dotenv/config";
import { createApp } from "./app.js";
import { createDatabase } from "./db.js";

const db = createDatabase();
const app = createApp({ db });
const port = Number(process.env.PORT ?? 4174);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}

const server = app.listen(port, "127.0.0.1", () => {
  console.log(`WebGuard API listening at http://127.0.0.1:${port}`);
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
