import { pino } from 'pino';
import type { SpearLogger } from './types/index.js';

export function createLogger(name: string, verbose = false): SpearLogger {
  const level = verbose ? 'debug' : 'info';
  const logger = pino({
    name,
    level,
    transport: {
      target: 'pino/file',
      options: { destination: 2 }, // stderr
    },
    formatters: {
      level: (label) => ({ level: label }),
    },
  });

  return {
    debug: (msg, data) => logger.debug(data ?? {}, msg),
    info: (msg, data) => logger.info(data ?? {}, msg),
    warn: (msg, data) => logger.warn(data ?? {}, msg),
    error: (msg, data) => logger.error(data ?? {}, msg),
  };
}
