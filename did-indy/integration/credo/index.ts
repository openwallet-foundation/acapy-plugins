import {
  InitConfig,
  Agent,
  KeyDerivationMethod,
  ConsoleLogger,
  LogLevel,
  ConnectionEventTypes,
  HttpOutboundTransport,
  ConnectionsModule,
  PeerDidNumAlgo,
  CreateOutOfBandInvitationConfig,
  HandshakeProtocol,
  CredentialsModule,
  AutoAcceptCredential,
  JsonLdCredentialFormatService,
  DifPresentationExchangeProofFormatService,
  V2CredentialProtocol,
  W3cCredentialsModule,
  ProofsModule,
  V2ProofProtocol,
  CredentialEventTypes,
  ProofEventTypes,
  AutoAcceptProof,
  DidsModule,
  PeerDidResolver,
  PeerDidRegistrar,
  DocumentLoader,
  AgentContext,
  DidsApi,
  CredoError,
  JsonTransformer
} from '@credo-ts/core';
import {
  IndyVdrIndyDidResolver,
  IndyVdrModule,
  IndyVdrModuleConfig,
} from '@credo-ts/indy-vdr'
import { HttpInboundTransport, agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import { TCPSocketServer, JsonRpcApiProxy } from 'json-rpc-api-proxy';
import validatePDv1 from '@sphereon/pex/dist/main/lib/validation/validatePDv1'
import { indyVdr } from '@hyperledger/indy-vdr-nodejs';
import { genesis } from './genesis';

let agent: Agent | null = null;
const server = new TCPSocketServer({
  host: process.env.AFJ_HOST || '0.0.0.0',
  port: parseInt(process.env.AFJ_PORT || '3000'),
});
const proxy = new JsonRpcApiProxy(server);

proxy.rpc.addMethod('initialize', async (): Promise<{}> => {
  if (agent !== null) {
    console.warn('Agent already initialized');
    return {};
  }

  const key = ariesAskar.storeGenerateRawKey({});

  const config: InitConfig = {
    label: 'test-agent',
    logger: new ConsoleLogger(LogLevel.debug),
    endpoints: [process.env.AFJ_ENDPOINT || 'http://localhost:3000'],
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

  const jsonLdCredentialFormat = new JsonLdCredentialFormatService()
  const difPresentationFormat = new DifPresentationExchangeProofFormatService()
  agent = new Agent({
    config,
    dependencies: agentDependencies,
    modules: {
      // Register the Askar module on the agent
      askar: new AskarModule({
        ariesAskar,
      }),
      indy: new IndyVdrModule({
        indyVdr,
        networks: [{
          isProduction: false,
          genesisTransactions: genesis,
          indyNamespace: 'indicio:test',
          transactionAuthorAgreement: {
            version: '1',
            acceptanceMechanism: 'accept'
          }
        }]
      }),
      dids: new DidsModule({
        registrars: [new PeerDidRegistrar()],
        resolvers: [new PeerDidResolver(), new IndyVdrIndyDidResolver()]
      }),
      connections: new ConnectionsModule({
        peerNumAlgoForDidExchangeRequests: PeerDidNumAlgo.ShortFormAndLongForm
      }),
      credentials: new CredentialsModule({
        autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
        credentialProtocols: [
          new V2CredentialProtocol({
            credentialFormats: [jsonLdCredentialFormat],
          }),
        ],
      }),
      w3cCredentials: new W3cCredentialsModule(),
      proofs: new ProofsModule({
        autoAcceptProofs: AutoAcceptProof.ContentApproved,
        proofProtocols: [
          new V2ProofProtocol({
            proofFormats: [difPresentationFormat],
          }),
        ],
      }),
    },
  });

  agent.registerOutboundTransport(new HttpOutboundTransport());
  agent.registerInboundTransport(new HttpInboundTransport({port: parseInt(process.env.AFJ_MESSAGE_PORT || '3001')}));

  const eventPassThrough = (type: string) => {
    agent?.events.on(type, async (event) => {
        proxy.rpc.notify("event." + type, event)
      }
    )
  };

  eventPassThrough(ConnectionEventTypes.ConnectionStateChanged)
  eventPassThrough(CredentialEventTypes.CredentialStateChanged)
  eventPassThrough(ProofEventTypes.ProofStateChanged)

  await agent.initialize();
  return {};
});


const getAgent = () => {
  if (agent === null) {
    throw new Error('Agent not initialized');
  }
  return agent;
};


proxy.rpc.addMethod('receiveInvitation', async ({invitation}: {invitation: string}) => {
  const agent = getAgent();
  const {outOfBandRecord} = await agent.oob.receiveInvitationFromUrl(invitation);
  return outOfBandRecord;
});

proxy.rpc.addMethod('createInvitation', async () => {
  const agent = getAgent();
  const config: CreateOutOfBandInvitationConfig = {
    handshake: true,
    handshakeProtocols: [HandshakeProtocol.DidExchange],
    autoAcceptConnection: true,
  }
  const outOfBandRecord = await agent.oob.createInvitation(config);
  return outOfBandRecord;
});

proxy.rpc.addMethod('resolve', async({did}: {did: string}) => {
  const agent = getAgent();
  const result = await agent.dids.resolve(did);
  return result.didDocument;
});

proxy.rpc.addMethod(
  'credentials.acceptOffer',
  async ({credentialRecordId}: {credentialRecordId: string}) => {
    const agent = getAgent();
    await agent.credentials.acceptOffer({credentialRecordId})
  }
)

proxy.rpc.addMethod(
  'proofs.acceptRequest',
  async ({proofRecordId}: {proofRecordId: string}) => {
    const agent = getAgent();
    await agent.proofs.acceptRequest({proofRecordId})
  }
)

proxy.rpc.addMethod(
  'validatePresentationDefinition',
  async ({definition}: {definition: any}) => {
    const result = validatePDv1(definition)
    console.log('Validation details:')
    console.log(definition)
    console.log(JSON.stringify((validatePDv1 as any).errors, null, 2))
    return result
  }
)

proxy.start();
