import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import type { StateController } from '../../src/twin.js';

export const CANARY_USER_A = 'CANARY_USER_A_7F4C';
export const CANARY_USER_B = 'CANARY_USER_B_2A11';
/** An owned egress-canary token embedded in the SSRF probe URL. */
export const CANARY_EGRESS = 'CANARY_EGRESS_9D3E';

interface FixtureItem {
  id: string;
  owner: string;
  tenant: string;
  canary: string;
}

const ITEMS: FixtureItem[] = [
  { id: 'item-a', owner: 'user-a', tenant: 'tenant-a', canary: CANARY_USER_A },
  { id: 'item-b', owner: 'user-b', tenant: 'tenant-b', canary: CANARY_USER_B },
];

/**
 * A disposable two-tenant HTTP fixture that doubles as the Twin StateController.
 *
 * `vulnerable: true` omits every authorization check so BOLA/BFLA reproduce;
 * `vulnerable: false` binds each effect to the authenticated principal so the
 * same attack programs are rejected. Reset and snapshot run in-process — a
 * control path independent of the attacked HTTP surface — so replay integrity
 * is verified without trusting the routes under attack.
 */
export class HttpFixture implements StateController {
  readonly vulnerable: boolean;
  readonly #server: Server;
  readonly #controlServer: Server;
  #reindexCount = 0;
  #adminCount = 0;
  #canarySinkHits = 0;
  #canarySink = '';
  #orderCount = 0;
  #configValue = 'initial';
  #debitTotal = 0;
  #creditTotal = 0;
  #shippedCount = 0;
  #unpaidShipments = 0;
  #paid = false;
  #meCache: string | undefined;
  readonly #seenKeys = new Set<string>();
  #origin = '';
  #controlOrigin = '';

  constructor(options: { vulnerable: boolean }) {
    this.vulnerable = options.vulnerable;
    this.#server = createServer((req, res) => {
      this.#handle(req, res).catch(() => this.#json(res, 500, { error: 'internal' }));
    });
    this.#controlServer = createServer((req, res) => this.#handleControl(req, res));
  }

  get origin(): string {
    if (!this.#origin) throw new Error('HttpFixture is not listening');
    return this.#origin;
  }

  /** The owned control-plane origin, independent of the attacked surface. */
  get controlOrigin(): string {
    if (!this.#controlOrigin) throw new Error('HttpFixture is not listening');
    return this.#controlOrigin;
  }

  #listenOne(server: Server): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.removeListener('error', reject);
        resolve((server.address() as AddressInfo).port);
      });
    });
  }

  async listen(): Promise<string> {
    const [attackPort, controlPort] = await Promise.all([
      this.#listenOne(this.#server),
      this.#listenOne(this.#controlServer),
    ]);
    this.#origin = `http://127.0.0.1:${attackPort}`;
    this.#controlOrigin = `http://127.0.0.1:${controlPort}`;
    return this.#origin;
  }

  async close(): Promise<void> {
    await Promise.all([
      new Promise<void>((resolve, reject) => {
        this.#server.close((error) => (error ? reject(error) : resolve()));
      }),
      new Promise<void>((resolve, reject) => {
        this.#controlServer.close((error) => (error ? reject(error) : resolve()));
      }),
    ]);
  }

  #state(): Record<string, unknown> {
    return {
      reindexCount: this.#reindexCount,
      adminCount: this.#adminCount,
      canarySinkHits: this.#canarySinkHits,
      canarySink: this.#canarySink,
      orderCount: this.#orderCount,
      configValue: this.#configValue,
      debitTotal: this.#debitTotal,
      creditTotal: this.#creditTotal,
      shippedCount: this.#shippedCount,
      unpaidShipments: this.#unpaidShipments,
    };
  }

  async snapshot(): Promise<Record<string, unknown>> {
    return this.#state();
  }

  async reset(): Promise<void> {
    this.#reindexCount = 0;
    this.#adminCount = 0;
    this.#canarySinkHits = 0;
    this.#canarySink = '';
    this.#orderCount = 0;
    this.#configValue = 'initial';
    this.#debitTotal = 0;
    this.#creditTotal = 0;
    this.#shippedCount = 0;
    this.#unpaidShipments = 0;
    this.#paid = false;
    this.#meCache = undefined;
    this.#seenKeys.clear();
  }

  #actor(req: IncomingMessage): string {
    const header = req.headers['authorization'];
    if (typeof header !== 'string') return 'anonymous';
    return header.replace(/^Fixture\s+/u, '').trim() || 'anonymous';
  }

  async #readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    if (chunks.length === 0) return {};
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', this.#origin || 'http://127.0.0.1');
    const actor = this.#actor(req);

    if (req.method === 'GET' && url.pathname.startsWith('/items/')) {
      const id = url.pathname.slice('/items/'.length);
      const item = ITEMS.find((candidate) => candidate.id === id);
      if (!item) return this.#json(res, 404, { error: 'not-found' });
      if (!this.vulnerable && actor !== item.owner) {
        return this.#json(res, 403, { error: 'forbidden' });
      }
      return this.#json(res, 200, { id: item.id, owner: item.owner, canary: item.canary });
    }

    // Differential authorization (S6/FR-507): an admin-only report with no
    // per-principal marker. Vulnerable mode returns the identical report to any
    // authenticated actor (broken function-level authz); fixed mode restricts it
    // to `admin`. The only cross-principal signal is response equivalence.
    if (req.method === 'GET' && url.pathname === '/admin/report') {
      if (!this.vulnerable && actor !== 'admin') {
        return this.#json(res, 403, { error: 'forbidden' });
      }
      return this.#json(res, 200, { report: 'fleet-wide-metrics', total: 42 });
    }

    if (req.method === 'POST' && url.pathname === '/admin/reindex') {
      if (!this.vulnerable && actor !== 'admin') {
        return this.#json(res, 403, { error: 'forbidden' });
      }
      this.#reindexCount += 1;
      return this.#json(res, 200, { accepted: true });
    }

    // Mass assignment (BOPLA): a user updates their own profile, but a `role`
    // field in the body must never take effect. Vulnerable mode blindly applies
    // every submitted property; fixed mode only accepts allow-listed fields.
    if (req.method === 'POST' && url.pathname === '/profile') {
      const body = await this.#readJsonBody(req);
      const applied: Record<string, unknown> = { displayName: body.displayName ?? actor };
      if (this.vulnerable && 'role' in body) {
        applied.role = body.role;
        if (body.role === 'admin') this.#adminCount += 1;
      }
      return this.#json(res, 200, { applied });
    }

    // SSRF: a user submits a URL the server will fetch. Vulnerable mode fetches
    // any URL (hitting the owned canary sink); fixed mode refuses off-list URLs.
    if (req.method === 'POST' && url.pathname === '/fetch') {
      const body = await this.#readJsonBody(req);
      const requested = typeof body.url === 'string' ? body.url : '';
      if (!this.vulnerable) return this.#json(res, 403, { error: 'ssrf-blocked' });
      if (requested) {
        this.#canarySinkHits += 1; // the owned canary sink observed a hit
        this.#canarySink = requested; // ...carrying whatever token the probe URL held
      }
      return this.#json(res, 200, { fetched: Boolean(requested) });
    }

    // Idempotency (S5/FR-806): a create endpoint. Vulnerable mode ignores the
    // Idempotency-Key and creates on every call; fixed mode dedups by key.
    if (req.method === 'POST' && url.pathname === '/order') {
      await this.#readJsonBody(req);
      const key = req.headers['idempotency-key'];
      if (!this.vulnerable && typeof key === 'string' && this.#seenKeys.has(key)) {
        return this.#json(res, 200, { deduped: true });
      }
      if (typeof key === 'string') this.#seenKeys.add(key);
      this.#orderCount += 1;
      return this.#json(res, 200, { created: true });
    }

    // Non-numeric state change (S6/FR-504): unauthorized config rotation. Vulnerable
    // mode applies any value; fixed mode denies non-privileged actors.
    if (req.method === 'POST' && url.pathname === '/rotate') {
      const body = await this.#readJsonBody(req);
      if (!this.vulnerable && actor !== 'admin') {
        return this.#json(res, 403, { error: 'forbidden' });
      }
      if (typeof body.value === 'string') this.#configValue = body.value;
      return this.#json(res, 200, { rotated: true });
    }

    // GraphQL carrier (FR-411): a node(id) query. Vulnerable mode returns any
    // node's canary regardless of the caller; fixed mode denies cross-owner reads.
    if (req.method === 'POST' && url.pathname === '/graphql') {
      const body = await this.#readJsonBody(req);
      const variables = (body.variables && typeof body.variables === 'object')
        ? body.variables as Record<string, unknown>
        : {};
      const id = typeof variables.id === 'string' ? variables.id : '';
      const item = ITEMS.find((candidate) => candidate.id === id);
      if (!item) return this.#json(res, 200, { data: { node: null } });
      if (!this.vulnerable && actor !== item.owner) {
        return this.#json(res, 200, { data: { node: null }, errors: [{ message: 'forbidden' }] });
      }
      return this.#json(res, 200, { data: { node: { id: item.id, canary: item.canary } } });
    }

    // Partial-effect / non-atomic commit (S6b/FR-509): a two-step transfer
    // (debit then credit). When the credit step is induced to fail, vulnerable
    // mode leaves the debit committed (partial effect); fixed mode rolls back.
    if (req.method === 'POST' && url.pathname === '/transfer') {
      const body = await this.#readJsonBody(req);
      const amount = typeof body.amount === 'number' ? body.amount : 0;
      const failCredit = body.failCredit === true;
      if (this.vulnerable) {
        this.#debitTotal += amount; // committed before the credit step
        if (failCredit) return this.#json(res, 500, { error: 'credit-failed' });
        this.#creditTotal += amount;
        return this.#json(res, 200, { transferred: true });
      }
      if (failCredit) return this.#json(res, 500, { error: 'credit-failed' }); // atomic: nothing applied
      this.#debitTotal += amount;
      this.#creditTotal += amount;
      return this.#json(res, 200, { transferred: true });
    }

    // Workflow step-skip (FR-414): shipping must be preceded by payment.
    // Vulnerable mode ships without checking `paid`; fixed mode requires it.
    if (req.method === 'POST' && url.pathname === '/pay') {
      this.#paid = true;
      return this.#json(res, 200, { paid: true });
    }
    if (req.method === 'POST' && url.pathname === '/ship') {
      if (!this.vulnerable && !this.#paid) {
        return this.#json(res, 402, { error: 'payment-required' });
      }
      this.#shippedCount += 1;
      if (!this.#paid) this.#unpaidShipments += 1; // only reachable in vulnerable mode
      return this.#json(res, 200, { shipped: true });
    }

    // Cache poisoning / cross-principal cached response (FR-416): /me is cached by
    // path only. Vulnerable mode serves any actor the cached body; fixed mode keys
    // the cache per actor.
    if (req.method === 'GET' && url.pathname === '/me') {
      const own = ITEMS.find((candidate) => candidate.owner === actor);
      const body = own ? own.canary : 'anonymous';
      if (this.vulnerable) {
        if (this.#meCache === undefined) this.#meCache = body;
        return this.#json(res, 200, { me: this.#meCache });
      }
      return this.#json(res, 200, { me: body });
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      return this.#json(res, 200, { ok: true });
    }

    return this.#json(res, 404, { error: 'not-found' });
  }

  // Control plane: independent of the attacked routes, used by the Twin to
  // snapshot and reset disposable state over an owned origin.
  #handleControl(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? '/', this.#controlOrigin || 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/state') {
      return this.#json(res, 200, this.#state());
    }
    if (req.method === 'POST' && url.pathname === '/reset') {
      void this.reset();
      return this.#json(res, 200, { ok: true });
    }
    return this.#json(res, 404, { error: 'not-found' });
  }

  #json(res: ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload),
    });
    res.end(payload);
  }
}
