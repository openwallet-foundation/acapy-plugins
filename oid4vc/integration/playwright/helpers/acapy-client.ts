/**
 * ACA-Py Client - Helper functions for interacting with ACA-Py admin API.
 * 
 * Provides methods for credential issuance and verification setup.
 */

import axios from 'axios';
import type { AxiosInstance } from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { fileURLToPath } from 'url';

// ESM compatible __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ISSUER_ADMIN_URL = process.env.ACAPY_ISSUER_ADMIN_URL || 'http://localhost:8021';
const VERIFIER_ADMIN_URL = process.env.ACAPY_VERIFIER_ADMIN_URL || 'http://localhost:8031';
const ISSUER_OID4VCI_URL = process.env.ACAPY_ISSUER_OID4VCI_URL || 'http://localhost:8022';
const VERIFIER_OID4VP_URL = process.env.ACAPY_VERIFIER_OID4VP_URL || 'http://localhost:8032';

function createClient(baseUrl: string): AxiosInstance {
  return axios.create({
    baseURL: baseUrl,
    headers: { 'Content-Type': 'application/json' },
    timeout: 30000,
  });
}

// ============================================================================
// Issuer Functions
// ============================================================================

/**
 * Create a DID for the issuer (P-256 for mDOC)
 */
export async function createIssuerDid(keyType: string = 'p256'): Promise<string> {
  const client = createClient(ISSUER_ADMIN_URL);
  const response = await client.post('/wallet/did/create', {
    method: 'key',
    options: { key_type: keyType },
  });
  return response.data.result.did;
}

/**
 * Create mDOC (mDL) credential configuration
 */
export async function createMdocCredentialConfig(configId?: string): Promise<string> {
  const client = createClient(ISSUER_ADMIN_URL);
  
  const id = configId || `org.iso.18013.5.1.mDL_waltid_${Date.now()}`;
  
  const config = {
    id,
    format: 'mso_mdoc',
    scope: 'mDL',
    doctype: 'org.iso.18013.5.1.mDL',
    cryptographic_binding_methods_supported: ['cose_key', 'did:key', 'did'],
    cryptographic_suites_supported: ['ES256'],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ['ES256'],
      },
    },
    format_data: {
      doctype: 'org.iso.18013.5.1.mDL',
      claims: {
        'org.iso.18013.5.1': {
          family_name: { mandatory: true },
          given_name: { mandatory: true },
          birth_date: { mandatory: true },
          issuing_country: { mandatory: true },
          issuing_authority: { mandatory: true },
          document_number: { mandatory: true },
        },
      },
      display: [
        {
          name: 'Mobile Driving License',
          locale: 'en-US',
          description: 'ISO 18013-5 compliant mobile driving license',
        },
      ],
    },
  };
  
  const response = await client.post('/oid4vci/credential-supported/create', config);
  return response.data.supported_cred_id;
}

/**
 * Create SD-JWT credential configuration
 */
export async function createSdJwtCredentialConfig(configId?: string): Promise<string> {
  const client = createClient(ISSUER_ADMIN_URL);
  
  const id = configId || `TestCredential_waltid_${Date.now()}`;
  
  const config = {
    id,
    format: 'vc+sd-jwt',
    scope: 'TestCredential',
    // These belong at top level, not inside format_data
    cryptographic_binding_methods_supported: ['did:key'],
    cryptographic_suites_supported: ['EdDSA', 'ES256'],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ['EdDSA', 'ES256'],
      },
    },
    display: [
      {
        name: 'Test Credential',
        locale: 'en-US',
        description: 'A test credential for walt.id integration',
      },
    ],
    format_data: {
      vct: 'TestCredential',
      // Include types array as a fallback for wallets that don't handle VCT URL resolution
      // The walt.id wallet checks for types first, then credential_definition.type, then vct
      types: ['VerifiableCredential', 'TestCredential'],
      // For SD-JWT VC, use "claims" internally (processor validates against this)
      // The to_issuer_metadata() will output it as credentialSubject for walt.id compatibility
      claims: {
        given_name: { mandatory: true },
        family_name: { mandatory: true },
        email: { mandatory: false },
      },
    },
    vc_additional_data: {
      sd_list: ['/given_name', '/family_name', '/email'],
    },
  };
  
  const response = await client.post('/oid4vci/credential-supported/create', config);
  return response.data.supported_cred_id;
}

/**
 * Create JWT-VC credential configuration
 */
export async function createJwtVcCredentialConfig(configId?: string): Promise<string> {
  const client = createClient(ISSUER_ADMIN_URL);
  
  const id = configId || `JWTVCCredential_waltid_${Date.now()}`;
  
  const config = {
    id,
    format: 'jwt_vc_json',
    scope: 'JWTVCCredential',
    // These belong at top level, not inside format_data
    cryptographic_binding_methods_supported: ['did:key'],
    cryptographic_suites_supported: ['EdDSA', 'ES256'],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ['EdDSA', 'ES256'],
      },
    },
    display: [
      {
        name: 'JWT-VC Test Credential',
        locale: 'en-US',
        description: 'A JWT-VC test credential for walt.id integration',
      },
    ],
    format_data: {
      // credential_definition fields: @context, type, credentialSubject
      types: ['VerifiableCredential', 'TestCredential'],
      context: [
        'https://www.w3.org/2018/credentials/v1',
      ],
      // Use credentialSubject for jwt_vc_json, not claims
      credentialSubject: {
        given_name: { mandatory: true },
        family_name: { mandatory: true },
      },
    },
  };
  
  const response = await client.post('/oid4vci/credential-supported/create', config);
  return response.data.supported_cred_id;
}

/**
 * Create a credential exchange and get the offer URL
 */
export async function createCredentialOffer(
  supportedCredId: string,
  issuerDid: string,
  credentialSubject: Record<string, any>
): Promise<{ exchangeId: string; offerUrl: string }> {
  const client = createClient(ISSUER_ADMIN_URL);
  
  // Create exchange
  const exchangeResponse = await client.post('/oid4vci/exchange/create', {
    supported_cred_id: supportedCredId,
    did: issuerDid,
    credential_subject: credentialSubject,
  });
  
  const exchangeId = exchangeResponse.data.exchange_id;
  
  // Get offer
  const offerResponse = await client.get('/oid4vci/credential-offer', {
    params: { exchange_id: exchangeId },
  });
  
  return {
    exchangeId,
    offerUrl: offerResponse.data.credential_offer,
  };
}

/**
 * Generate mDOC signing keys (issuer will auto-generate self-signed certificate)
 */
export async function generateMdocSigningKeys(): Promise<{ keyId: string; certId: string }> {
  const client = createClient(ISSUER_ADMIN_URL);
  
  try {
    // Try to generate keys - if they already exist, this will return existing ones
    const response = await client.post('/mso_mdoc/generate-keys');
    return {
      keyId: response.data.key_id,
      certId: response.data.cert_id,
    };
  } catch (error: any) {
    // If endpoint doesn't exist or fails, try to continue without explicit key generation
    // The mDOC processor may auto-generate keys on first issuance
    console.log('Note: mDOC key generation skipped or using auto-generated keys');
    return { keyId: 'auto', certId: 'auto' };
  }
}

/**
 * Legacy function for backward compatibility - now calls generateMdocSigningKeys
 * @deprecated Use generateMdocSigningKeys instead
 */
export async function uploadIssuerCertificate(_certPath?: string, _keyPath?: string): Promise<void> {
  await generateMdocSigningKeys();
}

// ============================================================================
// Verifier Functions
// ============================================================================

/**
 * Upload trust anchor certificate to verifier for mDOC verification
 */
export async function uploadTrustAnchor(certPath?: string): Promise<void> {
  const client = createClient(VERIFIER_ADMIN_URL);
  
  try {
    const certsDir = path.resolve(__dirname, '../certs');
    const certPem = fs.readFileSync(certPath || path.join(certsDir, 'root-ca.pem'), 'utf-8');
    
    // Use the mso_mdoc trust anchor endpoint
    await client.post('/mso_mdoc/trust-anchors', {
      certificate_pem: certPem,
      anchor_id: `playwright_test_${Date.now()}`,
    });
  } catch (error: any) {
    // Ignore if trust anchor already exists or endpoint not available
    console.log('Note: Trust anchor upload skipped or already exists');
  }
}

/**
 * Create mDOC presentation request
 */
export async function createMdocPresentationRequest(): Promise<{ presentationId: string; requestUrl: string }> {
  const client = createClient(VERIFIER_ADMIN_URL);
  
  const presentationDefinition = {
    id: randomUUID(),
    format: { mso_mdoc: { alg: ['ES256'] } },
    input_descriptors: [
      {
        id: 'org.iso.18013.5.1.mDL',
        format: { mso_mdoc: { alg: ['ES256'] } },
        constraints: {
          limit_disclosure: 'required',
          fields: [
            { path: ["$['org.iso.18013.5.1']['given_name']"] },
            { path: ["$['org.iso.18013.5.1']['family_name']"] },
          ],
        },
      },
    ],
  };
  
  // Step 1: Create presentation definition
  const presDefResponse = await client.post('/oid4vp/presentation-definition', {
    pres_def: presentationDefinition,
  });
  
  const presDefId = presDefResponse.data.pres_def_id;
  
  // Step 2: Create request using the presentation definition ID
  const response = await client.post('/oid4vp/request', {
    pres_def_id: presDefId,
    vp_formats: { mso_mdoc: { alg: ['ES256'] } },
  });
  
  return {
    presentationId: response.data.presentation.presentation_id,
    requestUrl: response.data.request_uri,
  };
}

/**
 * Create SD-JWT presentation request
 */
export async function createSdJwtPresentationRequest(): Promise<{ presentationId: string; requestUrl: string }> {
  const client = createClient(VERIFIER_ADMIN_URL);
  
  const presentationDefinition = {
    id: randomUUID(),
    format: { 'vc+sd-jwt': { 'sd-jwt_alg_values': ['ES256', 'EdDSA'] } },
    input_descriptors: [
      {
        id: 'sdjwt-cred',
        format: { 'vc+sd-jwt': { 'sd-jwt_alg_values': ['ES256', 'EdDSA'] } },
        constraints: {
          limit_disclosure: 'required',
          fields: [
            { path: ['$.vct', '$.vc.type'], filter: { type: 'string', pattern: 'TestCredential' } },
            { path: ['$.given_name', '$.credentialSubject.given_name'] },
          ],
        },
      },
    ],
  };
  
  // Step 1: Create presentation definition
  const presDefResponse = await client.post('/oid4vp/presentation-definition', {
    pres_def: presentationDefinition,
  });
  
  const presDefId = presDefResponse.data.pres_def_id;
  
  // Step 2: Create request using the presentation definition ID
  const response = await client.post('/oid4vp/request', {
    pres_def_id: presDefId,
    vp_formats: { vc_sd_jwt: { alg: ['ES256', 'EdDSA'] } },
  });
  
  return {
    presentationId: response.data.presentation.presentation_id,
    requestUrl: response.data.request_uri,
  };
}

/**
 * Create JWT-VC presentation request
 */
export async function createJwtVcPresentationRequest(): Promise<{ presentationId: string; requestUrl: string }> {
  const client = createClient(VERIFIER_ADMIN_URL);
  
  const presentationDefinition = {
    id: randomUUID(),
    format: { jwt_vc_json: { alg: ['ES256', 'EdDSA'] } },
    input_descriptors: [
      {
        id: 'jwtvc-cred',
        format: { jwt_vc_json: { alg: ['ES256', 'EdDSA'] } },
        constraints: {
          fields: [
            { path: ['$.vc.type'], filter: { type: 'array', contains: { const: 'TestCredential' } } },
          ],
        },
      },
    ],
  };
  
  // Step 1: Create presentation definition
  const presDefResponse = await client.post('/oid4vp/presentation-definition', {
    pres_def: presentationDefinition,
  });
  
  const presDefId = presDefResponse.data.pres_def_id;
  
  // Step 2: Create request using the presentation definition ID
  const response = await client.post('/oid4vp/request', {
    pres_def_id: presDefId,
    vp_formats: { jwt_vc_json: { alg: ['ES256', 'EdDSA'] } },
  });
  
  return {
    presentationId: response.data.presentation.presentation_id,
    requestUrl: response.data.request_uri,
  };
}

/**
 * Get presentation state (single check, no polling)
 */
export async function getPresentationState(presentationId: string): Promise<any> {
  const client = createClient(VERIFIER_ADMIN_URL);
  const response = await client.get(`/oid4vp/presentation/${presentationId}`);
  return response.data;
}

/**
 * Poll for presentation state
 */
export async function waitForPresentationState(
  presentationId: string,
  expectedState: string = 'presentation-valid',
  maxRetries: number = 30,
  intervalMs: number = 1000
): Promise<any> {
  const client = createClient(VERIFIER_ADMIN_URL);
  
  for (let i = 0; i < maxRetries; i++) {
    const response = await client.get(`/oid4vp/presentation/${presentationId}`);
    const state = response.data.state;
    
    if (state === expectedState) {
      return response.data;
    }
    
    if (state === 'presentation-invalid' || state === 'error') {
      throw new Error(`Presentation failed with state: ${state}`);
    }
    
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  
  throw new Error(`Presentation did not reach state ${expectedState} after ${maxRetries} retries`);
}

/**
 * Wait for ACA-Py services to be healthy
 */
export async function waitForAcaPyServices(maxRetries: number = 30): Promise<void> {
  const issuerClient = createClient(ISSUER_ADMIN_URL);
  const verifierClient = createClient(VERIFIER_ADMIN_URL);
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      const [issuerReady, verifierReady] = await Promise.all([
        issuerClient.get('/status/ready'),
        verifierClient.get('/status/ready'),
      ]);
      
      if (issuerReady.data.ready && verifierReady.data.ready) {
        return;
      }
    } catch (error) {
      // Continue retrying
    }
    
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  throw new Error('ACA-Py services not ready after max retries');
}
