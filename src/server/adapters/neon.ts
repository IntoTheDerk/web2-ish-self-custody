/**
 * Vercel + Neon wiring.
 *
 * `neon` is injected rather than imported so this package keeps zero runtime
 * dependency on `@neondatabase/serverless`. Nothing in the SDK may import a
 * driver at module scope; the host owns that choice, which is what makes the
 * same code liftable to self-hosted PostgreSQL.
 */

import type { IdentityService } from "../contract.js";
import { createIdentityService } from "../service.js";
import { neonDriver, type NeonQueryable } from "../sql.js";
import type { IdentityServiceConfig, SecondFactorIdentityServiceConfig } from "../types.js";

/** Structural shape of `neon` from `@neondatabase/serverless`. */
export type NeonClientFactory = (connectionString: string) => NeonQueryable;

export type NeonIdentityServiceOptions = Readonly<{
  connectionString: string;
  /** A `SecondFactorIdentityServiceConfig` makes an `IdentityService<true>`. */
  config: IdentityServiceConfig | SecondFactorIdentityServiceConfig;
  /** Pass the imported `neon` factory directly. */
  neon: NeonClientFactory;
}>;

export function createNeonIdentityService(
  options: NeonIdentityServiceOptions & Readonly<{ config: SecondFactorIdentityServiceConfig }>,
): IdentityService<true>;
export function createNeonIdentityService(
  options: NeonIdentityServiceOptions & Readonly<{ config: IdentityServiceConfig }>,
): IdentityService;
export function createNeonIdentityService(
  options: NeonIdentityServiceOptions,
): IdentityService<boolean>;
export function createNeonIdentityService(
  options: NeonIdentityServiceOptions,
): IdentityService<boolean> {
  return createIdentityService(
    neonDriver(options.neon(options.connectionString)),
    options.config,
  );
}
