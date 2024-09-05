import {
  InitConfig,
  Agent,
  KeyDerivationMethod,
  ConsoleLogger,
  LogLevel,
  W3cCredentialsModule,
  DidsModule,
  PeerDidResolver,
  PeerDidRegistrar,
  W3cCredentialRecord,
  SdJwtVcRecord,
  DifPresentationExchangeService,
  JwkDidResolver,
  JwkDidCreateOptions,
  JwkDidRegistrar,
} from '@credo-ts/core';
import { KeyDidCreateOptions, getJwkFromKey, DidKey } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import { OpenId4VcHolderModule, OpenId4VciCredentialFormatProfile } from '@credo-ts/openid4vc';
import { TCPSocketServer, JsonRpcApiProxy } from 'json-rpc-api-proxy';

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

  agent = new Agent({
    config,
    dependencies: agentDependencies,
    modules: {
      // Register the Askar module on the agent
      askar: new AskarModule({
        ariesAskar,
      }),
      dids: new DidsModule({
        registrars: [new PeerDidRegistrar(), new JwkDidRegistrar()],
        resolvers: [new PeerDidResolver(), new JwkDidResolver()]
      }),
      openId4VcHolderModule: new OpenId4VcHolderModule(),
      w3cCredentials: new W3cCredentialsModule(),
    },
  });

  await agent.initialize();
  return {};
});


const getAgent = () => {
  if (agent === null) {
    throw new Error('Agent not initialized');
  }
  return agent;
};

proxy.rpc.addMethod(
  'openid4vci.acceptCredentialOffer',
  async ({offer}: {offer: string}) => {
    const agent = getAgent();

    // resolved credential offer contains the offer, metadata, etc..
    const resolvedCredentialOffer = await agent.modules.openId4VcHolderModule.resolveCredentialOffer(offer)
    console.log('Resolved credential offer', JSON.stringify(resolvedCredentialOffer.credentialOfferPayload, null, 2))

    // issuer only supports pre-authorized flow for now
    const credentials = await agent.modules.openId4VcHolderModule.acceptCredentialOfferUsingPreAuthorizedCode(
      resolvedCredentialOffer,
      {
        credentialBindingResolver: async ({
          supportedDidMethods,
          keyType,
          supportsAllDidMethods,
          // supportsJwk now also passed
          supportsJwk,
          credentialFormat,
        }: {
          supportedDidMethods: any,
          keyType: any,
          supportsAllDidMethods: any,
          // supportsJwk now also passed
          supportsJwk: any,
          credentialFormat: any,
        }) => {
          // NOTE: example implementation. Adjust based on your needs
          // Return the binding to the credential that should be used. Either did or jwk is supported

          if (supportsAllDidMethods || supportedDidMethods?.includes('did:key')) {
            const didResult = await agent.dids.create<JwkDidCreateOptions>({
              method: 'jwk',
              options: {
                keyType,
              },
            })

            if (didResult.didState.state !== 'finished') {
              throw new Error('DID creation failed.')
            }

            const did = didResult.didState.did

            return {
              method: 'did',
              didUrl: `${did}#0`,
            }
          }

          // we also support plain jwk for sd-jwt only
          if (supportsJwk && credentialFormat === OpenId4VciCredentialFormatProfile.SdJwtVc) {
            const key = await agent.wallet.createKey({
              keyType,
            })

            // you now need to return an object instead of VerificationMethod instance
            // and method 'did' or 'jwk'
            return {
              method: 'jwk',
              jwk: getJwkFromKey(key),
            }
          }

          throw new Error('Unable to create a key binding')
        },
      }
    )

    console.log('Received credentials', JSON.stringify(credentials, null, 2))

    // Store the received credentials
    const records: Array<W3cCredentialRecord | SdJwtVcRecord> = []
    for (const credential of credentials) {
      if ('compact' in credential) {
        const record = await agent.sdJwtVc.store(credential.compact)
        records.push(record)
      } else {
        const record = await agent.w3cCredentials.storeCredential({
          credential,
        })
        records.push(record)
      }
    }
  }
)

proxy.rpc.addMethod(
  'openid4vci.acceptAuthorizationRequest',
  async ({request}: {request: string}) => {
    const agent = getAgent()
    const resolvedAuthorizationRequest = await agent.modules.openId4VcHolderModule.resolveSiopAuthorizationRequest(
      request
    )
    console.log(
      'Resolved credentials for request',
      JSON.stringify(resolvedAuthorizationRequest.presentationExchange.credentialsForRequest, null, 2)
    )

    const presentationExchangeService = agent.dependencyManager.resolve(DifPresentationExchangeService)
    // Automatically select credentials. In a wallet you could manually choose which credentials to return based on the "resolvedAuthorizationRequest.presentationExchange.credentialsForRequest" value
    const selectedCredentials = presentationExchangeService.selectCredentialsForRequest(
      resolvedAuthorizationRequest.presentationExchange.credentialsForRequest
    )

    // issuer only supports pre-authorized flow for now
    const authorizationResponse = await agent.modules.openId4VcHolderModule.acceptSiopAuthorizationRequest({
      authorizationRequest: resolvedAuthorizationRequest.authorizationRequest,
      presentationExchange: {
        credentials: selectedCredentials,
      },
    })
    console.log('Submitted authorization response', JSON.stringify(authorizationResponse.submittedResponse, null, 2))
  }
)

proxy.start();
