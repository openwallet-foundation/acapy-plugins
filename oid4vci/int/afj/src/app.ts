import { JSONRPCClient, JSONRPCServer, JSONRPCServerAndClient, JSONRPCServerMiddleware, createJSONRPCErrorResponse } from 'json-rpc-2.0';
import {
  InitConfig,
  Agent,
  KeyDerivationMethod,
  ConsoleLogger,
  LogLevel,
  KeyDidCreateOptions,
  KeyType,
  DidKey,
  JwaSignatureAlgorithm,
} from '@aries-framework/core';
import { agentDependencies } from '@aries-framework/node';
import { AskarModule } from '@aries-framework/askar';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import { TCPSocketServer } from './server';
import { OpenId4VcClientApi, OpenId4VcClientModule } from '@aries-framework/openid4vc-client';

let agent: Agent | null;
const server = new TCPSocketServer({
  host: process.env.AFJ_HOST || '0.0.0.0',
  port: parseInt(process.env.AFJ_PORT || '3000'),
})

const rpc = new JSONRPCServerAndClient(
  new JSONRPCServer(),
  new JSONRPCClient((request) => {
    server.send(JSON.stringify(request));
  })
);

server.ondata((data) => {
  return rpc.receiveAndSend(JSON.parse(data));
})

server.onclose(() => {
  rpc.rejectAllPendingRequests("Socket closed");
})

const logMiddleware: JSONRPCServerMiddleware<void> = async (next, request, serverParams) => {
  console.log(`Received ${JSON.stringify(request)}`);
  return next(request, serverParams).then((response) => {
    console.log(`Responding ${JSON.stringify(response)}`);
    return response;
  });
};

const exceptionMiddleware: JSONRPCServerMiddleware<void> = async (next, request, serverParams) => {
  try {
    return await next(request, serverParams);
  } catch (error: unknown) {
    // Report ALL exceptions with details
    console.error(error);
    let errorMessage = "Unknown error";
    if (error instanceof Error) {
      errorMessage = error.stack ?? error.message;
    }
    return createJSONRPCErrorResponse(
      request.id ?? null,
      -32000,
      'Internal server error',
      errorMessage
    )
  }
}
rpc.applyServerMiddleware(logMiddleware, exceptionMiddleware)

process.on('SIGINT', function() {
  console.log('Received SIGINT. Shutting down gracefully.');
  // Close your server or any other cleanup logic here
  server.stop()
});


interface InitializeParams {
}
interface InitializeResult {
}
rpc.addMethod('initialize', async ({}: InitializeParams): Promise<InitializeResult> => {
  const key = ariesAskar.storeGenerateRawKey({});

  const config: InitConfig = {
    label: 'test-agent',
    logger: new ConsoleLogger(LogLevel.debug),
    walletConfig: {
      id: 'test',
      key: key,
      keyDerivationMethod: KeyDerivationMethod.Raw,
      storage: {
        type: 'sqlite',
        inMemory: true,
      },
    },
  };

  agent = new Agent({
    config,
    dependencies: agentDependencies,
    modules: {
      // Register the Askar module on the agent
      askar: new AskarModule({
        ariesAskar,
      }),
      openId4VcClient: new OpenId4VcClientModule(),
    },
  });

  await agent.initialize();
  return {};
});

rpc.addMethod('requestCredentialUsingPreAuthorized', async ({issuerUri}: {issuerUri: string}): Promise<Record<string, unknown>> => {
  if (!agent) {
    throw new Error('Agent not initialized');
  }

  const did = await agent.dids.create<KeyDidCreateOptions>({
    method: 'key',
    options: {
      keyType: KeyType.Ed25519,
    }
  })
  console.log(did)

  const didKey = DidKey.fromDid(did.didState.did as string)
  const kid = `${did.didState.did as string}#${didKey.key.fingerprint}`
  const verificationMethod = did.didState.didDocument?.dereferenceKey(kid, ['authentication'])
  if (!verificationMethod) throw new Error('No verification method found')

  const openId4VcClient = agent.dependencyManager.resolve(OpenId4VcClientApi)
  const w3cCredentialRecords = await openId4VcClient.requestCredentialUsingPreAuthorizedCode({
    issuerUri,
    verifyCredentialStatus: false,
    allowedProofOfPossessionSignatureAlgorithms: [JwaSignatureAlgorithm.EdDSA],
    proofOfPossessionVerificationMethodResolver: () => verificationMethod,
  })
  return w3cCredentialRecords[0].toJSON()
})

server.start();
