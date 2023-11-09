import { createServer, Server, Socket } from 'net';

class MessageBuffer {
  private buffer: Buffer = Buffer.alloc(0);
  private headerSize: number | null = null;
  public onMessage?: (message: string) => void = undefined;

  public append(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
    this.processBuffer();
  }

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

interface ServerConfig {
  socketPath: string;
}

type Handler = (data: string) => Promise<void>;

export abstract class BaseSocketServer {
  protected server: Server;
  protected handlers: Handler[] = [];
  protected closeHandlers: (() => void)[] = [];
  protected sockets: Set<Socket> = new Set();

  constructor() {
    this.server = createServer(socket => {
      const messageBuffer = new MessageBuffer();

      messageBuffer.onMessage = (message) => {
        for (const handler of this.handlers) {
          handler(message).then();
        }
      }

      socket.on('data', data => {
        messageBuffer.append(data);
      });

      socket.on('close', () => {
        this.sockets.delete(socket);
        for (const handler of this.closeHandlers) {
          handler();
        }
      });

      socket.on('error', (err) => {
        console.error('Socket error:', err);
      });

      this.sockets.add(socket);
    });
  }

  public abstract start(): void;

  public stop(): void {
    this.server.close(() => {
      console.log('Closed out remaining connections.');
    });

    setTimeout(() => {
      console.error('Could not close connections in time, forcefully shutting down');
    }, 10000);
  }

  public ondata(handler: Handler): void {
    this.handlers.push(handler);
  }

  public onclose(handler: () => void): void {
    this.closeHandlers.push(handler);
  }

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

interface UnixServerConfig {
  socketPath: string;
}

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


interface TCPServerConfig {
  host: string;
  port: number;
}

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
