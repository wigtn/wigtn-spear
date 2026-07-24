export class SpearConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SpearConfigError';
  }
}

export class SpearSafetyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SpearSafetyError';
  }
}

export class SpearExecutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SpearExecutionError';
  }
}
