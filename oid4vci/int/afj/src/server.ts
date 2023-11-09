import { createServer, Server, Socket } from 'net';

/**
 * A handler function that processes string data.
 * @callback Handler
 * @param {string} data - The data string to process.
 * @returns {Promise<void>} A promise that resolves when the processing is complete.
 */
type Handler = (data: string) => Promise<void>;

/**
 * Defines the interface for transport layer implementations.
 * @interface
 */
export interface Transport {
  start(): void;
  stop(): Promise<void>;
  ondata(handler: Handler): void;
  onclose(handler: () => void): void;
  send(data: string): void;
}

/**
 * Buffers incoming data and processes it to extract messages based on a header format.
 * @class
 */
class MessageBuffer {
  private buffer: Buffer = Buffer.alloc(0);
  private headerSize: number | null = null;

  /**
   * Callback for when a complete message is available.
   * @public
   */
  public onMessage?: (message: string) => void = undefined;

  /**
   * Appends incoming data to the buffer and processes it.
   * @param {Buffer} data - The incoming data buffer.
   * @public
   */
  public append(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
    this.processBuffer();
  }

  /**
   * Processes the buffer to extract messages.
   * @private
   */
  private processBuffer(): void {
    while (true) {
      if (this.headerSize === null) {
        const headerEnd = this.buffer.indexOf('\n');
        if (headerEnd !== -1) {
          const header = this.buffer.subarray(0, headerEnd).toString();
          const match = header.match(/^length: (\d+)/);
          if (match) {
            this.headerSize = Number(match[1]);
            this.buffer = this.buffer.subarray(headerEnd + 1); // +1 for the new line
          } else {
            throw new Error('Invalid message header');
          }
        } else {
          // Not enough data to read the header yet
          break;
        }
      }

      // If we have determined the headerSize, see if we have enough buffer to read it
      if (this.headerSize !== null && this.buffer.length >= this.headerSize) {
        const message = this.buffer.subarray(0, this.headerSize).toString();
        this.buffer = this.buffer.subarray(this.headerSize);
        this.headerSize = null; // Reset for the next message

        // Emit the 'message' event with the complete message
        if (!this.onMessage) {
          throw new Error('No message handler set');
        }
        this.onMessage(message);
      } else {
        // Not enough data to read the full message yet
        break;
      }
    }
  }
}

/**
 * An abstract base class for socket server transports that implement the Transport interface.
 * @class
 * @abstract
 */
export abstract class BaseSocketServer implements Transport {
  protected server: Server;
  protected handlers: Handler[] = [];
  protected closeHandlers: (() => void)[] = [];
  protected sockets: Set<Socket> = new Set();

  constructor() {
    this.server = createServer(socket => {
      const messageBuffer = new MessageBuffer();

      messageBuffer.onMessage = message => {
        for (const handler of this.handlers) {
          handler(message).then();
        }
      };

      socket.on('data', data => {
        messageBuffer.append(data);
      });

      socket.on('close', () => {
        this.sockets.delete(socket);
        for (const handler of this.closeHandlers) {
          handler();
        }
      });

      socket.on('error', err => {
        console.error('Socket error:', err);
      });

      this.sockets.add(socket);
    });
  }

  /**
   * Abstract method to start the server. Must be implemented by subclasses.
   * @abstract
   */
  public abstract start(): void;

  /**
   * Stops the server and all associated connections.
   * @returns {Promise<void>} A promise that resolves when the server is stopped.
   * @public
   */
  public stop(): Promise<void> {
    this.server.close(() => {
      console.log('Closed out remaining connections.');
      return Promise.resolve();
    });

    setTimeout(() => {
      console.error('Could not close connections in time, forcefully shutting down');
    }, 10000);
    return Promise.reject('Server did not stop in time');
  }

  /**
   * Registers a data handler.
   * @param {Handler} handler - The handler function to register.
   * @public
   */
  public ondata(handler: Handler): void {
    this.handlers.push(handler);
  }

  /**
   * Registers a close handler.
   * @param {() => void} handler - The handler function to call when the server closes.
   * @public
   */
  public onclose(handler: () => void): void {
    this.closeHandlers.push(handler);
  }

  /**
   * Sends data to all connected sockets.
   * @param {string} data - The data string to send.
   * @public
   */
  public send(data: string): void {
    const buffer = Buffer.from(data);
    const header = `length: ${buffer.length}\n`;
    const headerBuffer = Buffer.from(header);
    const message = Buffer.concat([headerBuffer, buffer]);

    for (const socket of this.sockets) {
      socket.write(message);
    }
  }
}

/**
 * Configuration for creating a Unix socket server.
 * @property {string} socketPath - The file system path to the Unix socket.
 */
interface UnixServerConfig {
  socketPath: string;
}

/**
 * Server implementation for Unix socket transport.
 * @class
 * @extends BaseSocketServer
 */
export class UnixSocketServer extends BaseSocketServer {
  private config: UnixServerConfig;

  constructor(config: UnixServerConfig) {
    super();
    this.config = config;
  }

  public start(): void {
    this.server.listen(this.config.socketPath, () => {
      console.log(`Server listening on Unix socket ${this.config.socketPath}`);
    });
  }
}

/**
 * Configuration for creating a TCP server.
 * @property {string} host - The hostname or IP address.
 * @property {number} port - The port number.
 */
interface TCPServerConfig {
  host: string;
  port: number;
}

/**
 * Server implementation for TCP socket transport.
 * @class
 * @extends BaseSocketServer
 */
export class TCPSocketServer extends BaseSocketServer {
  private config: TCPServerConfig;

  constructor(config: TCPServerConfig) {
    super();
    this.config = config;
  }

  public start(): void {
    this.server.listen(this.config.port, this.config.host, () => {
      console.log(`Server listening on TCP ${this.config.host}:${this.config.port}`);
    });
  }
}
