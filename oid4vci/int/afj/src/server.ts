import { createServer, Server, Socket } from 'net';

interface ServerConfig {
  socketPath: string;
}

type Handler = (data: string) => Promise<void>;

export class SocketServer {
  private config: ServerConfig;
  private server: Server | undefined;
  private handlers: Handler[] = [];
  private closeHandlers: (() => void)[] = [];
  private sockets: Set<Socket> = new Set();

  constructor(config: ServerConfig) {
    this.config = config;
  }

  public start(): void {
    this.startSocketServer();
  }

  public stop(): void {
    this.server?.close(function() {
      console.log('Closed out remaining connections.');
      // End the process with success code (0)
      process.exit(0);
    });

    // If server is not finished within a certain time limit, 
    // force close the server and exit
    setTimeout(function() {
      console.error('Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, 10000); // 10 seconds
  }

  public ondata(handler: Handler): void {
    this.handlers.push(handler);
  }

  public onclose(handler: () => void): void {
    this.closeHandlers.push(handler);
  }

  public send(data: string): void {
    for (const socket of this.sockets) {
      socket.write(data);
    }
  }

  private startSocketServer(): void {
    this.server = createServer(socket => {
      this.sockets.add(socket);
      
      socket.on('data', data => {
        for (const handler of this.handlers) {
          handler(data.toString()).then();
        }
      });

      socket.on('close', () => {
        this.sockets.delete(socket);
        for (const handler of this.closeHandlers) {
          handler();
        }
      });
    });

    this.server.listen(this.config.socketPath, () => {
      console.log(`Server listening on socket ${this.config.socketPath}`);
    });
  }
}
