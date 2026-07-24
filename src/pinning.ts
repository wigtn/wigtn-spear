import { isIP } from 'node:net';
import { Agent, type Dispatcher } from 'undici';
import { SpearSafetyError } from './errors.js';

/**
 * Build an undici dispatcher that connects ONLY to the addresses SPEAR has
 * already pinned for each hostname. undici's connector calls our lookup instead
 * of the OS resolver, so between DNS revalidation and the actual socket connect
 * the destination cannot change (closes the DNS-rebinding TOCTOU / FR-801). The
 * Host header and TLS SNI stay bound to the original hostname.
 *
 * `pins` is read live at connect time, so re-pins during redirect revalidation
 * are honored. A hostname with no pin is refused before any socket opens.
 */
export function createPinnedDispatcher(pins: ReadonlyMap<string, readonly string[]>): Dispatcher {
  return new Agent({
    connect: {
      lookup(hostname, options, callback) {
        const addresses = pins.get(hostname);
        if (!addresses || addresses.length === 0) {
          callback(
            new SpearSafetyError(`Refusing to connect to unpinned host: ${hostname}`),
            // The remaining args are unused on error.
            '' as unknown as string,
            4,
          );
          return;
        }
        const resolved = addresses.map((address) => ({ address, family: isIP(address) }));
        if (options && (options as { all?: boolean }).all) {
          callback(null, resolved as never, undefined as never);
        } else {
          const first = resolved[0]!;
          callback(null, first.address as never, first.family as never);
        }
      },
    },
  });
}
