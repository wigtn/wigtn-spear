/**
 * Worker Thread Pool for Parallel Processing
 *
 * Manages a pool of Node.js Worker threads for CPU-intensive scan tasks.
 * Tasks are queued in FIFO order and dispatched to available workers.
 * If a worker crashes, its pending task is requeued automatically.
 *
 * The pool registers SIGINT/SIGTERM handlers for graceful shutdown,
 * waiting for in-flight tasks to complete before terminating workers.
 */

import { Worker } from 'node:worker_threads';
import { cpus } from 'node:os';
import { WORKER_DEFAULTS } from '@wigtn/shared';

/** A pending task in the queue */
interface QueuedTask<T = unknown> {
  /** Data to send to the worker */
  data: unknown;
  /** Resolve the promise when the worker completes */
  resolve: (value: T) => void;
  /** Reject the promise if the worker errors */
  reject: (reason: unknown) => void;
  /** Number of retry attempts (for crash recovery) */
  retries: number;
}

/** Maximum number of retries for a single task when a worker crashes */
const MAX_TASK_RETRIES = 2;

/**
 * WorkerPool manages a fixed-size pool of Worker threads.
 *
 * Usage:
 * ```ts
 * const pool = new WorkerPool('./scan-worker.js', 4);
 * const result = await pool.run({ file: 'foo.ts', rules: [...] });
 * await pool.shutdown();
 * ```
 */
export class WorkerPool {
  private readonly workers: Worker[] = [];
  private readonly busyFlags: boolean[] = [];
  private readonly taskQueue: QueuedTask[] = [];
  private readonly workerScript: string;
  private readonly poolSize: number;
  private shuttingDown: boolean = false;
  private shutdownPromise: Promise<void> | null = null;
  private signalHandlersRegistered: boolean = false;

  /**
   * Create a new WorkerPool.
   *
   * @param workerScript - Absolute path to the worker script file.
   *   The script must listen for 'message' events on parentPort
   *   and post results back via parentPort.postMessage().
   * @param size - Number of worker threads. Defaults to
   *   max(MIN_WORKERS, os.cpus().length - 1).
   */
  constructor(workerScript: string, size?: number) {
    this.workerScript = workerScript;
    this.poolSize = size ?? Math.max(
      WORKER_DEFAULTS.MIN_WORKERS,
      cpus().length - 1,
    );

    this.initializeWorkers();
    this.registerSignalHandlers();
  }

  /**
   * Submit a task to the worker pool.
   *
   * If a worker is available, the task starts immediately.
   * Otherwise, it is queued and will execute when a worker becomes free.
   *
   * @param data - The data to send to the worker thread.
   * @returns A promise that resolves with the worker's result.
   * @throws If the pool is shutting down or the worker errors.
   */
  run<T>(data: unknown): Promise<T> {
    if (this.shuttingDown) {
      return Promise.reject(new Error('WorkerPool is shutting down'));
    }

    return new Promise<T>((resolve, reject) => {
      const task: QueuedTask<T> = {
        data,
        resolve: resolve as (value: unknown) => void,
        reject,
        retries: 0,
      };

      // Try to dispatch immediately to an idle worker
      const workerIndex = this.findIdleWorker();
      if (workerIndex >= 0) {
        this.dispatchTask(workerIndex, task as QueuedTask);
      } else {
        this.taskQueue.push(task as QueuedTask);
      }
    });
  }

  /**
   * Gracefully shut down the pool.
   *
   * Waits for all in-flight tasks to complete, rejects all queued tasks,
   * then terminates all worker threads.
   *
   * @returns A promise that resolves when all workers have terminated.
   */
  async shutdown(): Promise<void> {
    if (this.shutdownPromise) {
      return this.shutdownPromise;
    }

    this.shuttingDown = true;

    this.shutdownPromise = this.performShutdown();
    return this.shutdownPromise;
  }

  /**
   * Get the number of currently busy workers.
   */
  get activeTasks(): number {
    return this.busyFlags.filter(Boolean).length;
  }

  /**
   * Get the number of tasks waiting in the queue.
   */
  get queuedTasks(): number {
    return this.taskQueue.length;
  }

  /**
   * Get the total pool size.
   */
  get size(): number {
    return this.poolSize;
  }

  /**
   * Initialize all worker threads.
   */
  private initializeWorkers(): void {
    for (let i = 0; i < this.poolSize; i++) {
      const worker = this.createWorker(i);
      this.workers.push(worker);
      this.busyFlags.push(false);
    }
  }

  /**
   * Create a single worker thread and set up its event handlers.
   */
  private createWorker(index: number): Worker {
    const worker = new Worker(this.workerScript);

    worker.on('message', (result: unknown) => {
      this.onWorkerComplete(index, result);
    });

    worker.on('error', (error: Error) => {
      this.onWorkerError(index, error);
    });

    worker.on('exit', (code: number) => {
      this.onWorkerExit(index, code);
    });

    return worker;
  }

  /**
   * Handle successful task completion from a worker.
   */
  private onWorkerComplete(index: number, result: unknown): void {
    const task = (this.workers[index] as WorkerWithTask)?.__currentTask;
    if (task) {
      task.resolve(result);
      delete (this.workers[index] as WorkerWithTask).__currentTask;
    }

    this.busyFlags[index] = false;
    this.dispatchNext(index);
  }

  /**
   * Handle worker error. Requeue the task if retries remain.
   */
  private onWorkerError(index: number, error: Error): void {
    const task = (this.workers[index] as WorkerWithTask)?.__currentTask;

    if (task) {
      delete (this.workers[index] as WorkerWithTask).__currentTask;

      if (task.retries < MAX_TASK_RETRIES && !this.shuttingDown) {
        // Requeue the task for retry
        task.retries++;
        this.taskQueue.unshift(task);
      } else {
        task.reject(error);
      }
    }

    this.busyFlags[index] = false;

    // The worker may have crashed; it will fire 'exit' next.
    // We handle re-creation in onWorkerExit.
  }

  /**
   * Handle worker exit. Recreate the worker if the pool is still active.
   */
  private onWorkerExit(index: number, code: number): void {
    if (this.shuttingDown) {
      return;
    }

    // Non-zero exit code means the worker crashed
    if (code !== 0) {
      // Replace the crashed worker with a fresh one
      const newWorker = this.createWorker(index);
      this.workers[index] = newWorker;
      this.busyFlags[index] = false;

      // Try to dispatch queued tasks to the new worker
      this.dispatchNext(index);
    }
  }

  /**
   * Find the index of an idle worker, or -1 if all are busy.
   */
  private findIdleWorker(): number {
    for (let i = 0; i < this.busyFlags.length; i++) {
      if (!this.busyFlags[i]) {
        return i;
      }
    }
    return -1;
  }

  /**
   * Dispatch a task to a specific worker.
   */
  private dispatchTask(workerIndex: number, task: QueuedTask): void {
    this.busyFlags[workerIndex] = true;
    (this.workers[workerIndex] as WorkerWithTask).__currentTask = task;
    this.workers[workerIndex]!.postMessage(task.data);
  }

  /**
   * Try to dispatch the next queued task to a specific worker.
   */
  private dispatchNext(workerIndex: number): void {
    if (this.taskQueue.length === 0 || this.shuttingDown) {
      return;
    }

    const nextTask = this.taskQueue.shift()!;
    this.dispatchTask(workerIndex, nextTask);
  }

  /**
   * Perform the actual shutdown sequence.
   */
  private async performShutdown(): Promise<void> {
    // Reject all queued tasks
    while (this.taskQueue.length > 0) {
      const task = this.taskQueue.shift()!;
      task.reject(new Error('WorkerPool shutting down: task cancelled'));
    }

    // Wait for in-flight tasks to complete (with a timeout)
    const maxWait = WORKER_DEFAULTS.TASK_TIMEOUT_MS;
    const start = Date.now();

    while (this.activeTasks > 0 && Date.now() - start < maxWait) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    // Terminate all workers
    const terminations = this.workers.map(async (worker) => {
      try {
        await worker.terminate();
      } catch {
        // Worker may already be dead; ignore
      }
    });

    await Promise.all(terminations);

    // Clean up signal handlers
    this.removeSignalHandlers();
  }

  /**
   * Register SIGINT/SIGTERM handlers for graceful shutdown.
   */
  private registerSignalHandlers(): void {
    if (this.signalHandlersRegistered) return;

    this.boundSignalHandler = () => {
      void this.shutdown();
    };

    process.on('SIGINT', this.boundSignalHandler);
    process.on('SIGTERM', this.boundSignalHandler);
    this.signalHandlersRegistered = true;
  }

  /**
   * Remove signal handlers to prevent memory leaks.
   */
  private removeSignalHandlers(): void {
    if (!this.signalHandlersRegistered || !this.boundSignalHandler) return;

    process.off('SIGINT', this.boundSignalHandler);
    process.off('SIGTERM', this.boundSignalHandler);
    this.signalHandlersRegistered = false;
  }

  /** Bound reference to the signal handler for cleanup */
  private boundSignalHandler: (() => void) | null = null;
}

/**
 * Internal type extension to track the current task on a Worker instance.
 * This avoids maintaining a separate Map<number, QueuedTask>.
 */
interface WorkerWithTask extends Worker {
  __currentTask?: QueuedTask;
}
