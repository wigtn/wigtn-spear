import { SpearConfigError } from './errors.js';
import type {
  MappingSource,
  Surface,
  SurfaceInput,
  SurfaceInventory,
  TargetProfile,
} from './types.js';
import {
  asRecord,
  surfaceId,
  validateSurfaceInput,
  validateTargetProfile,
} from './validation.js';
import { isRecord } from './utils.js';

const HTTP_METHODS = new Set([
  'get',
  'put',
  'post',
  'delete',
  'options',
  'head',
  'patch',
  'trace',
]);

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function normalizeSurface(input: SurfaceInput, defaultSource: MappingSource): Surface {
  const operation = (input.operation ?? '*').toUpperCase();
  return {
    id: surfaceId(input.protocol, input.entryPoint, operation),
    protocol: input.protocol,
    entryPoint: input.entryPoint,
    operation,
    principals: sortedUnique(input.principals ?? []),
    dataClasses: sortedUnique(input.dataClasses ?? []),
    stateDependencies: sortedUnique(input.stateDependencies ?? []),
    applicablePacks: sortedUnique(input.applicablePacks ?? []),
    mappingSources: [input.mappingSource ?? defaultSource],
  };
}

function mergeSurface(current: Surface, incoming: Surface): Surface {
  return {
    ...current,
    principals: sortedUnique([...current.principals, ...incoming.principals]),
    dataClasses: sortedUnique([...current.dataClasses, ...incoming.dataClasses]),
    stateDependencies: sortedUnique([
      ...current.stateDependencies,
      ...incoming.stateDependencies,
    ]),
    applicablePacks: sortedUnique([...current.applicablePacks, ...incoming.applicablePacks]),
    mappingSources: sortedUnique([
      ...current.mappingSources,
      ...incoming.mappingSources,
    ]) as MappingSource[],
  };
}

export function surfacesFromOpenApi(input: unknown): SurfaceInput[] {
  const document = asRecord(input, 'openapi');
  const version = document.openapi;
  if (typeof version !== 'string' || !version.startsWith('3.')) {
    throw new SpearConfigError('Only OpenAPI 3.x JSON documents are supported');
  }
  const paths = asRecord(document.paths, 'openapi.paths');
  const surfaces: SurfaceInput[] = [];

  for (const [path, rawPathItem] of Object.entries(paths)) {
    if (!path.startsWith('/')) {
      throw new SpearConfigError(`OpenAPI path must start with "/": ${path}`);
    }
    if (!isRecord(rawPathItem)) continue;
    for (const [method, operation] of Object.entries(rawPathItem)) {
      if (!HTTP_METHODS.has(method.toLowerCase()) || !isRecord(operation)) continue;
      const security = operation.security ?? rawPathItem.security ?? document.security;
      const principals = Array.isArray(security) && security.length === 0
        ? ['anonymous']
        : ['authenticated-or-unknown'];
      surfaces.push({
        protocol: 'http',
        entryPoint: path,
        operation: method.toUpperCase(),
        principals,
        mappingSource: 'openapi',
      });
    }
  }
  return surfaces;
}

function requireStringArray(value: unknown, context: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.trim() === '')) {
    throw new SpearConfigError(`${context} must be an array of non-empty strings`);
  }
  return value as string[];
}

/**
 * Map a SPEAR Next.js route descriptor (emitted by a build step) to passive HTTP
 * surfaces: one per route-handler method, one per server action, and one per
 * middleware matcher (the auth boundary itself is an attack surface).
 */
export function surfacesFromNextRoutes(input: unknown): SurfaceInput[] {
  const document = asRecord(input, 'next-routes');
  if (document.framework !== undefined && document.framework !== 'next') {
    throw new SpearConfigError('next-routes.framework must be "next"');
  }
  if (!Array.isArray(document.routes)) {
    throw new SpearConfigError('next-routes.routes must be an array');
  }
  const surfaces: SurfaceInput[] = [];
  document.routes.forEach((raw, index) => {
    const route = asRecord(raw, `next-routes.routes[${index}]`);
    const kind = route.kind;
    if (kind === 'route-handler') {
      const path = route.path;
      if (typeof path !== 'string' || !path.startsWith('/')) {
        throw new SpearConfigError(`next-routes.routes[${index}].path must start with "/"`);
      }
      const methods = requireStringArray(route.methods, `next-routes.routes[${index}].methods`);
      const principals = route.public === true ? ['anonymous'] : ['authenticated-or-unknown'];
      for (const method of methods) {
        if (!HTTP_METHODS.has(method.toLowerCase())) {
          throw new SpearConfigError(`next-routes.routes[${index}] has unsupported method ${method}`);
        }
        surfaces.push({
          protocol: 'http',
          entryPoint: path,
          operation: method.toUpperCase(),
          principals,
          mappingSource: 'next-app',
        });
      }
    } else if (kind === 'server-action') {
      const id = route.id;
      if (typeof id !== 'string' || id.trim() === '') {
        throw new SpearConfigError(`next-routes.routes[${index}].id must be a non-empty string`);
      }
      surfaces.push({
        protocol: 'http',
        entryPoint: `action:${id}`,
        operation: 'POST',
        principals: ['authenticated-or-unknown'],
        mappingSource: 'next-app',
      });
    } else if (kind === 'middleware') {
      const matcher = requireStringArray(route.matcher, `next-routes.routes[${index}].matcher`);
      surfaces.push({
        protocol: 'http',
        entryPoint: `middleware:${matcher.join(',')}`,
        operation: '*',
        principals: ['anonymous'],
        mappingSource: 'next-app',
      });
    } else {
      throw new SpearConfigError(`next-routes.routes[${index}].kind is unsupported: ${String(kind)}`);
    }
  });
  return surfaces;
}

/**
 * Map a SPEAR Supabase descriptor to passive surfaces: one per table operation
 * (tables without RLS are reachable anonymously and carry an rls-disabled state
 * dependency) and one per storage bucket.
 */
export function surfacesFromSupabase(input: unknown): SurfaceInput[] {
  const document = asRecord(input, 'supabase');
  if (document.framework !== undefined && document.framework !== 'supabase') {
    throw new SpearConfigError('supabase.framework must be "supabase"');
  }
  const surfaces: SurfaceInput[] = [];
  if (document.tables !== undefined) {
    if (!Array.isArray(document.tables)) throw new SpearConfigError('supabase.tables must be an array');
    document.tables.forEach((raw, index) => {
      const table = asRecord(raw, `supabase.tables[${index}]`);
      const schema = typeof table.schema === 'string' && table.schema ? table.schema : 'public';
      const name = table.name;
      if (typeof name !== 'string' || name.trim() === '') {
        throw new SpearConfigError(`supabase.tables[${index}].name must be a non-empty string`);
      }
      const rlsEnabled = table.rlsEnabled === true;
      const operations = requireStringArray(table.operations, `supabase.tables[${index}].operations`);
      for (const operation of operations) {
        surfaces.push({
          protocol: 'database',
          entryPoint: `table:${schema}.${name}`,
          operation: operation.toUpperCase(),
          principals: rlsEnabled ? ['authenticated-or-unknown'] : ['anonymous'],
          dataClasses: ['tabular'],
          stateDependencies: rlsEnabled ? [] : ['rls-disabled'],
          mappingSource: 'supabase',
        });
      }
    });
  }
  if (document.storageBuckets !== undefined) {
    if (!Array.isArray(document.storageBuckets)) {
      throw new SpearConfigError('supabase.storageBuckets must be an array');
    }
    document.storageBuckets.forEach((raw, index) => {
      const bucket = asRecord(raw, `supabase.storageBuckets[${index}]`);
      const name = bucket.name;
      if (typeof name !== 'string' || name.trim() === '') {
        throw new SpearConfigError(`supabase.storageBuckets[${index}].name must be a non-empty string`);
      }
      surfaces.push({
        protocol: 'storage',
        entryPoint: `bucket:${name}`,
        operation: 'OBJECT',
        principals: bucket.public === true ? ['anonymous'] : ['authenticated-or-unknown'],
        dataClasses: ['blob'],
        mappingSource: 'supabase',
      });
    });
  }
  return surfaces;
}

/**
 * Map a SPEAR GraphQL schema descriptor to passive `graphql` surfaces: one per
 * query and one per mutation. Public operations are anonymous-reachable; others
 * carry an authenticated principal. GraphQL rides HTTP, so these surfaces are
 * attacked by the existing HTTP runner (POST to the GraphQL endpoint).
 */
export function surfacesFromGraphql(input: unknown): SurfaceInput[] {
  const document = asRecord(input, 'graphql');
  if (document.framework !== undefined && document.framework !== 'graphql') {
    throw new SpearConfigError('graphql.framework must be "graphql"');
  }
  const surfaces: SurfaceInput[] = [];
  const collect = (key: 'queries' | 'mutations', operation: string): void => {
    if (document[key] === undefined) return;
    if (!Array.isArray(document[key])) throw new SpearConfigError(`graphql.${key} must be an array`);
    (document[key] as unknown[]).forEach((raw, index) => {
      const field = asRecord(raw, `graphql.${key}[${index}]`);
      const name = field.name;
      if (typeof name !== 'string' || name.trim() === '') {
        throw new SpearConfigError(`graphql.${key}[${index}].name must be a non-empty string`);
      }
      surfaces.push({
        protocol: 'graphql',
        entryPoint: `${operation.toLowerCase()}:${name}`,
        operation,
        principals: field.public === true ? ['anonymous'] : ['authenticated-or-unknown'],
        mappingSource: 'graphql-schema',
      });
    });
  };
  collect('queries', 'QUERY');
  collect('mutations', 'MUTATION');
  return surfaces;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const LONG_HEX_RE = /^[0-9a-f]{24,}$/iu;

/** Collapse concrete identifiers in a path so /users/123 and /users/456 map to
 * one templated surface (/users/{id}) instead of exploding. Also normalizes
 * authored path variables (:id, {{var}}) so a Postman route and its captured
 * instances converge on the same entry point. */
function templatizePath(pathname: string): string {
  const segments = pathname.split('/').map((segment) => {
    if (segment === '') return segment;
    if (
      /^\d+$/u.test(segment)
      || UUID_RE.test(segment)
      || LONG_HEX_RE.test(segment)
      || segment.startsWith(':')
      || /^\{\{.+\}\}$/u.test(segment)
    ) {
      return '{id}';
    }
    return segment;
  });
  const joined = segments.join('/');
  return joined === '' ? '/' : joined;
}

/**
 * Map an HTTP Archive (HAR) capture — browser devtools / proxy traffic — to
 * passive HTTP surfaces: one per observed method + templated path. A request
 * carrying an Authorization or Cookie header is treated as authenticated, others
 * as anonymous. The HAR is assumed to be scoped to the target host; duplicate
 * captures of the same surface merge in the inventory (principals unioned).
 */
export function surfacesFromHar(input: unknown): SurfaceInput[] {
  const document = asRecord(input, 'har');
  const log = asRecord(document.log, 'har.log');
  if (!Array.isArray(log.entries)) {
    throw new SpearConfigError('har.log.entries must be an array');
  }
  const surfaces: SurfaceInput[] = [];
  log.entries.forEach((raw, index) => {
    const entry = asRecord(raw, `har.log.entries[${index}]`);
    const request = asRecord(entry.request, `har.log.entries[${index}].request`);
    const method = request.method;
    if (typeof method !== 'string' || !HTTP_METHODS.has(method.toLowerCase())) {
      throw new SpearConfigError(`har.log.entries[${index}].request.method is unsupported: ${String(method)}`);
    }
    const rawUrl = request.url;
    if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
      throw new SpearConfigError(`har.log.entries[${index}].request.url must be a non-empty string`);
    }
    let pathname: string;
    try {
      pathname = new URL(rawUrl).pathname;
    } catch {
      throw new SpearConfigError(`har.log.entries[${index}].request.url is not an absolute URL: ${rawUrl}`);
    }
    const headers = Array.isArray(request.headers) ? request.headers : [];
    const authenticated = headers.some((header) => {
      if (!isRecord(header) || typeof header.name !== 'string') return false;
      const name = header.name.toLowerCase();
      return name === 'authorization' || name === 'cookie';
    });
    surfaces.push({
      protocol: 'http',
      entryPoint: templatizePath(pathname),
      operation: method.toUpperCase(),
      principals: authenticated ? ['authenticated-or-unknown'] : ['anonymous'],
      mappingSource: 'har-capture',
    });
  });
  return surfaces;
}

/** Extract the path from a Postman URL, which may be a raw string or an object
 * with a `path` segment array. Returns undefined for a non-HTTP / unparseable URL. */
function postmanUrlPath(url: unknown): string | undefined {
  if (typeof url === 'string') {
    if (url.trim() === '') return undefined;
    try {
      return new URL(url).pathname;
    } catch {
      return url.startsWith('/') ? url.split('?')[0] : undefined;
    }
  }
  if (isRecord(url) && Array.isArray(url.path)) {
    const segments = url.path.filter((segment): segment is string => typeof segment === 'string');
    return `/${segments.join('/')}`;
  }
  return undefined;
}

/**
 * Map a Postman Collection (v2.1) to passive HTTP surfaces: one per request
 * (method + templated path), walking nested item folders. A request with a
 * non-`noauth` auth block or an Authorization header is authenticated. Path
 * variables (:id, {{var}}) are templatized so authored routes and their captured
 * instances converge; duplicates merge in the inventory.
 */
export function surfacesFromPostman(input: unknown): SurfaceInput[] {
  const document = asRecord(input, 'postman');
  if (!Array.isArray(document.item)) {
    throw new SpearConfigError('postman.item must be an array');
  }
  const surfaces: SurfaceInput[] = [];
  const walk = (items: unknown[], path: string): void => {
    items.forEach((raw, index) => {
      const item = asRecord(raw, `${path}[${index}]`);
      if (Array.isArray(item.item)) {
        walk(item.item, `${path}[${index}].item`);
        return;
      }
      if (item.request === undefined) return; // a folder or non-request entry
      const request = asRecord(item.request, `${path}[${index}].request`);
      const method = request.method;
      if (typeof method !== 'string' || !HTTP_METHODS.has(method.toLowerCase())) {
        throw new SpearConfigError(`${path}[${index}].request.method is unsupported: ${String(method)}`);
      }
      const pathname = postmanUrlPath(request.url);
      if (pathname === undefined) return; // skip non-HTTP / unparseable URLs
      const authBlock = isRecord(request.auth) ? request.auth.type : undefined;
      const headers = Array.isArray(request.header) ? request.header : [];
      const hasAuthHeader = headers.some(
        (header) => isRecord(header) && typeof header.key === 'string'
          && header.key.toLowerCase() === 'authorization',
      );
      const authenticated = (typeof authBlock === 'string' && authBlock !== 'noauth') || hasAuthHeader;
      surfaces.push({
        protocol: 'http',
        entryPoint: templatizePath(pathname),
        operation: method.toUpperCase(),
        principals: authenticated ? ['authenticated-or-unknown'] : ['anonymous'],
        mappingSource: 'postman',
      });
    });
  };
  walk(document.item, 'postman.item');
  return surfaces;
}

export interface DiscoverySources {
  openApi?: unknown;
  nextRoutes?: unknown;
  supabase?: unknown;
  graphql?: unknown;
  har?: unknown;
  postman?: unknown;
}

function buildInventory(
  profile: TargetProfile,
  candidates: SurfaceInput[],
  now: Date,
): SurfaceInventory {
  const merged = new Map<string, Surface>();
  for (const [index, raw] of candidates.entries()) {
    const input = validateSurfaceInput(raw, `discovery.surfaces[${index}]`);
    const normalized = normalizeSurface(input, 'operator');
    const current = merged.get(normalized.id);
    merged.set(normalized.id, current ? mergeSurface(current, normalized) : normalized);
  }
  const surfaces = [...merged.values()].sort((left, right) => left.id.localeCompare(right.id));
  const sources = sortedUnique(
    surfaces.flatMap((surface) => surface.mappingSources),
  ) as MappingSource[];
  const blindSpots = surfaces
    .filter((surface) => surface.protocol === 'unknown')
    .map((surface) => ({
      id: `blind-${surface.id}`,
      surfaceId: surface.id,
      reason: 'Operator declared a surface whose protocol has no supported mapper',
    }));

  return {
    schemaVersion: '3.0',
    kind: 'surface-inventory',
    target: profile.target,
    generatedAt: now.toISOString(),
    sources,
    surfaces,
    blindSpots,
  };
}

export function discoverSurfacesFrom(
  profileInput: unknown,
  sources: DiscoverySources = {},
  now = new Date(),
): SurfaceInventory {
  const profile: TargetProfile = validateTargetProfile(profileInput);
  const candidates: SurfaceInput[] = [
    ...profile.surfaces.map((surface) => ({ ...surface, mappingSource: 'operator' as const })),
  ];
  if (sources.openApi !== undefined) candidates.push(...surfacesFromOpenApi(sources.openApi));
  if (sources.nextRoutes !== undefined) candidates.push(...surfacesFromNextRoutes(sources.nextRoutes));
  if (sources.supabase !== undefined) candidates.push(...surfacesFromSupabase(sources.supabase));
  if (sources.graphql !== undefined) candidates.push(...surfacesFromGraphql(sources.graphql));
  if (sources.har !== undefined) candidates.push(...surfacesFromHar(sources.har));
  if (sources.postman !== undefined) candidates.push(...surfacesFromPostman(sources.postman));
  return buildInventory(profile, candidates, now);
}

export function discoverSurfaces(
  profileInput: unknown,
  openApiInput?: unknown,
  now = new Date(),
): SurfaceInventory {
  return discoverSurfacesFrom(
    profileInput,
    openApiInput !== undefined ? { openApi: openApiInput } : {},
    now,
  );
}
