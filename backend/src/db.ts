import "dotenv/config";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

const migrationPaths = [
  resolve(process.cwd(), "migrations/001_initial.sql"),
  resolve(process.cwd(), "backend/migrations/001_initial.sql"),
];
const migrationPath = (() => {
  const found = migrationPaths.find(existsSync);
  if (!found) throw new Error("Could not locate backend/migrations/001_initial.sql.");
  return found;
})();

export type AppDatabase = {
  exec(sql: string): void;
  prepare(sql: string): ReturnType<DatabaseSync["prepare"]>;
  transaction<T>(callback: () => T): () => T;
  pragma(sql: string): void;
  close(): void;
};

export function createDatabase(databasePath?: string): AppDatabase {
  const defaultPath = process.cwd().endsWith("backend")
    ? "data/webguard.db"
    : "backend/data/webguard.db";
  const resolvedPath = resolve(databasePath ?? process.env.DATABASE_PATH ?? defaultPath);
  mkdirSync(dirname(resolvedPath), { recursive: true });

  const native = new DatabaseSync(resolvedPath);
  const db: AppDatabase = {
    exec: (sql) => native.exec(sql),
    prepare: (sql) => native.prepare(sql),
    transaction: <T>(callback: () => T) => () => {
      native.exec("BEGIN");
      try {
        const result = callback();
        native.exec("COMMIT");
        return result;
      } catch (error) {
        native.exec("ROLLBACK");
        throw error;
      }
    },
    pragma: (sql) => native.exec(`PRAGMA ${sql}`),
    close: () => native.close(),
  };
  db.pragma("foreign_keys = ON");
  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
  `);

  const applied = db.prepare("SELECT 1 FROM schema_migrations WHERE version = 1").get();
  if (!applied) {
    const migration = readFileSync(migrationPath, "utf8");
    const applyMigration = db.transaction(() => {
      db.exec(migration);
      db.prepare("INSERT INTO schema_migrations (version) VALUES (1)").run();
    });
    applyMigration();
  }

  return db;
}
