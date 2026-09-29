/**
 * The portability seam.
 *
 * The identity service talks to PostgreSQL only through `SqlDriver`. Two
 * properties keep that boundary honest:
 *
 * 1. Every statement is parameterized positionally (`$1`, `$2`, ...), so the
 *    same SQL text runs unchanged on Neon's HTTP driver and on `pg`.
 * 2. Every mutation that needs atomicity is expressed as ONE statement using
 *    CTEs. Neon's HTTP transport has no interactive transactions; refusing to
 *    depend on them is what lets this service run on Vercel today and on a
 *    self-hosted pool later with no behavioral difference.
 *
 * Binary columns are always read with `encode(col, 'hex')` and written with
 * `decode($n, 'hex')`, so no driver-specific `bytea` decoding leaks in here.
 */

export type SqlParameter = string | number | boolean | null;

export type SqlRow = Record<string, unknown>;

export interface SqlDriver {
  /** Identifies the backing transport in errors and health output. */
  readonly kind: string;
  query<T extends SqlRow = SqlRow>(
    text: string,
    params?: readonly SqlParameter[],
  ): Promise<T[]>;
}

/** Structural shape of `neon()` from `@neondatabase/serverless`. */
export interface NeonQueryable {
  query(
    text: string,
    params?: readonly unknown[],
  ): Promise<unknown>;
}

/** Structural shape of a `pg` `Pool` or `Client`. */
export interface PgQueryable {
  query(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: SqlRow[] }>;
}

function rowsFromNeonResult(result: unknown): SqlRow[] {
  if (Array.isArray(result)) {
    return result as SqlRow[];
  }
  if (
    typeof result === "object" &&
    result !== null &&
    "rows" in result &&
    Array.isArray((result as { rows: unknown }).rows)
  ) {
    return (result as { rows: SqlRow[] }).rows;
  }
  throw new TypeError("Unexpected Neon query result shape.");
}

/**
 * Wraps `neon(connectionString)` for Vercel. Depending on configuration the
 * HTTP driver returns either a bare row array or a full result object, so both
 * shapes are normalized here.
 */
export function neonDriver(client: NeonQueryable): SqlDriver {
  return Object.freeze({
    kind: "neon-http",
    async query<T extends SqlRow = SqlRow>(
      text: string,
      params: readonly SqlParameter[] = [],
    ): Promise<T[]> {
      return rowsFromNeonResult(await client.query(text, params)) as T[];
    },
  });
}

/** Wraps a `pg` Pool for self-hosted PostgreSQL. */
export function pgDriver(client: PgQueryable): SqlDriver {
  return Object.freeze({
    kind: "pg",
    async query<T extends SqlRow = SqlRow>(
      text: string,
      params: readonly SqlParameter[] = [],
    ): Promise<T[]> {
      const result = await client.query(text, params);
      return result.rows as T[];
    },
  });
}

export function requireSingleRow<T extends SqlRow>(
  rows: readonly T[],
  onMissing: () => Error,
): T {
  const row = rows[0];
  if (row === undefined) {
    throw onMissing();
  }
  return row;
}

export function optionalRow<T extends SqlRow>(rows: readonly T[]): T | null {
  return rows[0] ?? null;
}

export function textColumn(row: SqlRow, column: string): string {
  const value = row[column];
  if (typeof value !== "string") {
    throw new TypeError(`Expected text column "${column}".`);
  }
  return value;
}

export function integerColumn(row: SqlRow, column: string): number {
  const value = row[column];
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }
  // `pg` returns bigint-typed columns as strings to avoid precision loss.
  if (typeof value === "string" && /^-?\d+$/u.test(value)) {
    return Number.parseInt(value, 10);
  }
  throw new TypeError(`Expected integer column "${column}".`);
}

export function instantColumn(row: SqlRow, column: string): Date {
  const value = row[column];
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }
  throw new TypeError(`Expected timestamp column "${column}".`);
}

export function optionalInstantColumn(row: SqlRow, column: string): Date | null {
  return row[column] === null || row[column] === undefined
    ? null
    : instantColumn(row, column);
}

export function optionalTextColumn(row: SqlRow, column: string): string | null {
  const value = row[column];
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== "string") {
    throw new TypeError(`Expected nullable text column "${column}".`);
  }
  return value;
}
