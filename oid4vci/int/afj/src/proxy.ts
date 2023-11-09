import {
  JSONRPCClient,
  JSONRPCRequest,
  JSONRPCResponse,
  JSONRPCServer,
  JSONRPCServerAndClient,
  JSONRPCServerMiddleware,
  JSONRPCServerMiddlewareNext,
  createJSONRPCErrorResponse,
} from 'json-rpc-2.0';
import { Transport } from './server';

/**
 * Middleware for logging JSON-RPC requests and responses.
 * It intercepts the RPC call chain to log the request and response objects.
 * This is useful for debugging and monitoring purposes to track the RPC activity.
 *
 * @param {JSONRPCServerMiddlewareNext<IJSONRPCRequest, any>} next - The next middleware function in the chain.
 * @param {IJSONRPCRequest} request - The JSON-RPC request object.
 * @returns {Promise<JSONRPCResponse>} - The promise of the JSON-RPC response object.
 */
const logMiddleware: JSONRPCServerMiddleware<void> = async (
  next: JSONRPCServerMiddlewareNext<void>,
  request: JSONRPCRequest,
  serverParams: void
): Promise<JSONRPCResponse | null> => {
  console.log(`Received ${JSON.stringify(request)}`);
  return next(request, serverParams).then(response => {
    console.log(`Responding ${JSON.stringify(response)}`);
    return response;
  });
};

/**
 * Middleware for handling exceptions in JSON-RPC requests.
 * It captures any exceptions thrown during the processing of an RPC request
 * and formats them into a proper JSON-RPC error response. This ensures that
 * the client receives a well-formed error object in accordance with the JSON-RPC specification.
 *
 * @param {JSONRPCServerMiddlewareNext<ServerParams>} next - The next middleware function in the chain.
 * @param {JSONRPCRequest} request - The JSON-RPC request object.
 * @param {ServerParams} serverParams - The server parameters.
 * @returns {JSONRPCResponsePromise>} - The promise of the JSON-RPC response object.
 */
const exceptionMiddleware: JSONRPCServerMiddleware<void> = async (
  next: JSONRPCServerMiddlewareNext<void>,
  request: JSONRPCRequest,
  serverParams: void
): Promise<JSONRPCResponse | null> => {
  try {
    return await next(request, serverParams);
  } catch (error: unknown) {
    // Report ALL exceptions with details
    console.error(error);
    let errorMessage = 'Unknown error';
    if (error instanceof Error) {
      errorMessage = error.stack ?? error.message;
    }
    return createJSONRPCErrorResponse(
      request.id ?? null,
      -32000,
      'Internal server error',
      errorMessage
    );
  }
};

/**
 * The `JsonRpcApiProxy` class provides a mechanism to set up a JSON-RPC server and client
 * that can communicate over a provided transport layer. It facilitates the creation of a
 * transport-based RPC (Remote Procedure Call) interface, enabling the calling of functions
 * on a remote server accessible through the transport.
 *
 * To use this class, you need to provide a `Transport` object that handles the actual data
 * sending and receiving. The `Transport` must implement two main functions: `send` for sending
 * data to the transport and `ondata` for handling incoming data. It should also handle `onclose`
 * events when the transport is closed.
 *
 * The class creates an RPC server and client, binds them together, and sets up middleware for
 * logging and exception handling. It also defines clean-up logic for server shutdown on receiving
 * a SIGINT signal (commonly issued by pressing Ctrl+C).
 *
 * The `start` method is used to initiate the transport, while the `stop` method can be called
 * to stop the transport and cleanup resources.
 *
 * Example usage:
 * ```
 * const transport = new SomeTransport();
 * const jsonRpcApiProxy = new JsonRpcApiProxy(transport);
 *
 * // Add a method to the RPC interface.
 * jsonRpcApiProxy.rpc.addMethod('methodName', async (params) => {
 *   // Implementation of the method.
 * });
 *
 * // Start the transport to begin listening for RPC calls.
 * jsonRpcApiProxy.start();
 *
 * // Optionally, stop the transport when you are done.
 * // This returns a promise that resolves once the transport has been stopped.
 * jsonRpcApiProxy.stop().then(() => {
 *   console.log('Transport stopped');
 * });
 * ```
 * Note that error handling and cleanup logic should be implemented within the transport's
 * `ondata` and `onclose` handlers, as well as in the SIGINT signal handler to ensure graceful
 * shutdowns.
 * @class
 * @property {Transport} transport - The transport layer object used for sending and receiving messages.
 * @property {JSONRPCServerAndClient} rpc - The JSON-RPC server and client instance for managing RPC calls.
 */
export class JsonRpcApiProxy {
  /**
   * The transport layer used by the JSON-RPC server and client to send and receive messages.
   * @private
   */
  private transport: Transport;

  /**
   * The JSON-RPC server and client instance for managing RPC calls.
   * @public
   */
  public rpc: JSONRPCServerAndClient;

  /**
   * Constructs the `JsonRpcApiProxy` with the provided transport layer.
   * Initializes the JSON-RPC server and client, sets up data listeners and
   * middleware, and handles transport close events.
   * @constructor
   * @param {Transport} transport - The transport layer for message passing.
   */
  constructor(transport: Transport) {
    this.transport = transport;
    this.rpc = new JSONRPCServerAndClient(
      new JSONRPCServer(),
      new JSONRPCClient(request => {
        this.transport.send(JSON.stringify(request));
      })
    );

    this.transport.ondata(data => {
      return this.rpc.receiveAndSend(JSON.parse(data));
    });

    this.transport.onclose(() => {
      this.rpc.rejectAllPendingRequests('Transport closed');
    });

    this.rpc.applyServerMiddleware(logMiddleware, exceptionMiddleware);

    process.on('SIGINT', () => {
      console.log('Received SIGINT. Shutting down gracefully.');
      // Close your server or any other cleanup logic here
      this.transport
        .stop()
        .then(() => {
          process.exit(0);
        })
        .catch(err => {
          console.error(err);
          process.exit(1);
        });
    });
  }

  /**
   * Starts the JSON-RPC transport, allowing it to send and receive messages.
   * @public
   * @returns {void}
   */
  public start(): void {
    this.transport.start();
  }

  /**
   * Stops the JSON-RPC transport and resolves once the transport layer has been successfully stopped.
   * @public
   * @returns {Promise<void>} - A promise that resolves when the transport is stopped.
   */
  public stop(): Promise<void> {
    return this.transport.stop();
  }
}
