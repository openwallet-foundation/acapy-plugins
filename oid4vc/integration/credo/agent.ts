// IMPORTANT: Import askar-nodejs first to register the native bindings
// before any credo-ts packages that depend on @openwallet-foundation/askar-shared
import { askar } from '@openwallet-foundation/askar-nodejs';

import {
  Agent,
  ConsoleLogger,
  LogLevel,
  W3cCredentialsModule,
  DidsModule,
  SdJwtVcModule,
  MdocModule,
  X509Module,
} from '@credo-ts/core';
import type { InitConfig } from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { OpenId4VcModule } from '@credo-ts/openid4vc';
import { v4 as uuidv4 } from 'uuid';
import { logger } from './logger.js';

let agent: Agent | null = null;

export const getAgent = () => {
  if (!agent) {
    throw new Error('Agent not initialized');
  }
  return agent;
}

/**
 * Add a trusted certificate to the agent's X509 module.
 * This allows dynamic trust anchor registration via API.
 * 
 * @param certificate PEM-encoded certificate string
 */
export const addTrustedCertificate = (certificate: string) => {
  const agentInstance = getAgent();
  agentInstance.x509.config.addTrustedCertificate(certificate);
  logger.debug('Added trusted certificate to X509 module');
};

/**
 * Set all trusted certificates, replacing any existing ones.
 * 
 * @param certificates Array of PEM-encoded certificate strings
 */
export const setTrustedCertificates = (certificates: string[]) => {
  const agentInstance = getAgent();
  agentInstance.x509.config.setTrustedCertificates(certificates);
  logger.debug(`Set ${certificates.length} trusted certificates in X509 module`);
};

/**
 * Get currently configured trusted certificates.
 * 
 * @returns Array of PEM-encoded certificate strings
 */
export const getTrustedCertificates = (): string[] => {
  const agentInstance = getAgent();
  return agentInstance.x509.config.trustedCertificates ?? [];
};

export const initializeAgent = async (port: number) => {
  if (agent) {
    logger.debug('Agent already initialized');
    return agent;
  }

  const config: InitConfig = {
    logger: new ConsoleLogger(LogLevel.info),
    allowInsecureHttpUrls: true,
  };

  const walletId = `credo-test-wallet-${uuidv4()}`;
  const walletKey = askar.storeGenerateRawKey({});

  const modules = {
    askar: new AskarModule({
      askar,
      store: {
        id: walletId,
        key: walletKey,
        keyDerivationMethod: 'raw',
        database: {
          type: 'sqlite',
          config: {
            inMemory: true,
          },
        },
      },
    }),
    w3cCredentials: new W3cCredentialsModule(),
    sdJwtVc: new SdJwtVcModule(),
    mdoc: new MdocModule(),
    // Start with no trusted certificates - they will be added via API
    x509: new X509Module({
      trustedCertificates: [],
    }),
    openid4vc: new OpenId4VcModule(),
    dids: new DidsModule(),
  };

  logger.debug('Modules passed:', Object.keys(modules));
  agent = new Agent({
    config,
    dependencies: agentDependencies,
    modules,
  });
  logger.debug('Agent modules:', Object.keys(agent.modules));

  await agent.initialize();
  logger.info('🚀 Credo agent initialized');
  return agent;
};
