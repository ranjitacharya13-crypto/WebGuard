import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import ipaddr from "ipaddr.js";
import { z } from "zod";

const domainSchema = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .transform((value) => value.toLowerCase().replace(/\.$/, ""))
  .refine((value) => !value.includes("://") && !value.includes("/") && !value.includes(":") && !value.includes("@"), {
    message: "Enter a domain name only, without a scheme, port, path, or credentials.",
  })
  .refine((value) => !isIP(value), { message: "IP addresses cannot be registered as targets." })
  .refine((value) => value.includes(".") && value.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)), {
    message: "Enter a valid public domain name.",
  })
  .refine((value) => !["localhost", "local", "internal", "test", "invalid"].some((suffix) => value === suffix || value.endsWith(`.${suffix}`)), {
    message: "Local and reserved domains cannot be registered.",
  });

export function parseDomain(value: unknown): string {
  return domainSchema.parse(value);
}

export async function resolvePublicAddresses(hostname: string): Promise<string[]> {
  const records = await lookup(hostname, { all: true, verbatim: true });
  if (records.length === 0) throw new Error("The target domain does not resolve to an IP address.");

  const addresses = records.map(({ address }) => {
    const parsed = ipaddr.parse(address);
    if (parsed instanceof ipaddr.IPv6 && parsed.isIPv4MappedAddress()) {
      return parsed.toIPv4Address().toString();
    }
    return address;
  });

  if (addresses.some((address) => ipaddr.parse(address).range() !== "unicast")) {
    throw new Error("The target resolves to a private or reserved address; the check was blocked.");
  }

  return [...new Set(addresses)];
}

export function safeDomainError(error: unknown): string {
  if (error instanceof z.ZodError) return error.issues[0]?.message ?? "Invalid domain.";
  if (error instanceof Error) return error.message;
  return "Target verification failed.";
}
