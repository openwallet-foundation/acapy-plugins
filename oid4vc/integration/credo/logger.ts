/**
 * Simple logger utility with configurable log levels.
 * Respects LOG_LEVEL environment variable.
 */

enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

class Logger {
  private level: LogLevel;

  constructor() {
    const envLevel = process.env.LOG_LEVEL?.toUpperCase() || 'INFO';
    this.level = LogLevel[envLevel as keyof typeof LogLevel] ?? LogLevel.INFO;
  }

  debug(...args: any[]) {
    if (this.level <= LogLevel.DEBUG) {
      console.log('[DEBUG]', ...args);
    }
  }

  info(...args: any[]) {
    if (this.level <= LogLevel.INFO) {
      console.log('[INFO]', ...args);
    }
  }

  warn(...args: any[]) {
    if (this.level <= LogLevel.WARN) {
      console.warn('[WARN]', ...args);
    }
  }

  error(...args: any[]) {
    if (this.level <= LogLevel.ERROR) {
      console.error('[ERROR]', ...args);
    }
  }
}

export const logger = new Logger();
