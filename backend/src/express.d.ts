import type { UserIdentity } from "./types.js";

declare global {
  namespace Express {
    interface Request {
      user?: UserIdentity;
    }
  }
}

export {};
