#!/usr/bin/env npx ts-node
/**
 * Create an mDoc OID4VCI credential offer URL.
 *
 * Usage:
 *   npx ts-node create-mdoc-offer.ts [--issuer-url URL] [--issuer-did DID] [--config-id ID] [--subject JSON]
 *
 * Examples:
 *   # Use all defaults
 *   npx ts-node create-mdoc-offer.ts
 *
 *   # Custom issuer
 *   npx ts-node create-mdoc-offer.ts \
 *     --issuer-url http://localhost:8022 \
 *     --issuer-did 'did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro'
 *
 *   # Custom credential subject (must be valid JSON)
 *   npx ts-node create-mdoc-offer.ts \
 *     --subject '{"org.iso.18013.5.1":{"given_name":"Bob","family_name":"Builder","birth_date":"1985-03-20","issuing_country":"US","issuing_authority":"Demo DMV","document_number":"DL-DEMO-002","issue_date":"2024-01-01","expiry_date":"2034-01-01"}}'
 *
 * Environment variables:
 *   ACAPY_ISSUER_ADMIN_URL - ACA-Py issuer admin URL (default: http://localhost:8021)
 *   ACAPY_ISSUER_OID4VCI_URL - ACA-Py issuer OID4VCI public URL (default: http://localhost:8022)
 */

const axios = require('axios');

// ── Config ────────────────────────────────────────────────────────────────────

const ISSUER_ADMIN_URL = process.env.ACAPY_ISSUER_ADMIN_URL || 'http://localhost:8021';
const ISSUER_OID4VCI_URL = process.env.ACAPY_ISSUER_OID4VCI_URL || 'http://localhost:8022';

// Default credential subject (Alice Holder with mDL)
const DEFAULT_SUBJECT = {
  'org.iso.18013.5.1': {
    given_name: 'Alice',
    family_name: 'Holder',
    birth_date: '1990-06-15',
    issuing_country: 'US',
    issuing_authority: 'Demo DMV',
    document_number: 'DL-DEMO-001',
    issue_date: new Date().toISOString().split('T')[0],
    expiry_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
      .toISOString()
      .split('T')[0],
    portrait:
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
    un_distinguishing_sign: 'USA',
    driving_privileges: [
      {
        vehicle_category_code: 'C',
        issue_date: '2020-01-01',
        expiry_date: '2030-01-01',
      },
    ],
  },
};

// ── Argument parsing ──────────────────────────────────────────────────────────

interface Args {
  issuerUrl: string;
  issuerDid: string | null;
  configId: string;
  subject: Record<string, any>;
}

function parseArgs(): Args {
  const args: Args = {
    issuerUrl: ISSUER_OID4VCI_URL,
    issuerDid: null,
    configId: 'org.iso.18013.5.1.mDL_demo',
    subject: DEFAULT_SUBJECT,
  };

  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    const next = process.argv[i + 1];

    switch (arg) {
      case '--issuer-url':
        if (next) {
          args.issuerUrl = next;
          i++;
        }
        break;

      case '--issuer-did':
        if (next) {
          args.issuerDid = next;
          i++;
        }
        break;

      case '--config-id':
        if (next) {
          args.configId = next;
          i++;
        }
        break;

      case '--subject':
        if (next) {
          try {
            args.subject = JSON.parse(next);
          } catch (err) {
            console.error(`❌ Invalid JSON for --subject: ${err}`);
            process.exit(1);
          }
          i++;
        }
        break;

      case '--help':
      case '-h':
        printUsage();
        process.exit(0);

      default:
        if (arg.startsWith('--')) {
          console.warn(`⚠️  Unknown option: ${arg}`);
        }
    }
  }

  return args;
}

function printUsage(): void {
  console.log(`
Create an mDoc OID4VCI credential offer URL.

Usage:
  npx ts-node create-mdoc-offer.ts [OPTIONS]

Options:
  --issuer-url URL        Credential issuer public URL (default: ${ISSUER_OID4VCI_URL})
  --issuer-did DID        Issuer DID (default: prompt if not available)
  --config-id ID          Credential config ID (default: org.iso.18013.5.1.mDL_demo)
  --subject JSON          Credential subject as JSON (default: demo Alice Holder)
  --help, -h              Show this help

Examples:
  # Use all defaults
  npx ts-node create-mdoc-offer.ts

  # Custom issuer
  npx ts-node create-mdoc-offer.ts \\
    --issuer-url http://localhost:8022 \\
    --issuer-did 'did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro'

  # Custom subject
  npx ts-node create-mdoc-offer.ts \\    --config-id org.iso.18013.5.1.mDL_demo \    --subject '{"org.iso.18013.5.1":{"given_name":"Bob","family_name":"Builder","birth_date":"1985-03-20","issuing_country":"US","issuing_authority":"Demo DMV","document_number":"DL-DEMO-002"}}'

Environment variables:
  ACAPY_ISSUER_ADMIN_URL    - ACA-Py issuer admin API (default: http://localhost:8021)
  ACAPY_ISSUER_OID4VCI_URL  - ACA-Py issuer OID4VCI endpoint (default: http://localhost:8022)
  `);
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function getCredentialConfigs(): Promise<any[]> {
  const client = axios.create({
    baseURL: ISSUER_ADMIN_URL,
    timeout: 10_000,
  });

  try {
    const response = await client.get('/oid4vci/credential-supported/records');
    return response.data.results || [];
  } catch (err) {
    console.error(`❌ Failed to fetch credential configs from ${ISSUER_ADMIN_URL}`);
    throw err;
  }
}

async function getIssuerDid(): Promise<string | null> {
  const client = axios.create({
    baseURL: ISSUER_ADMIN_URL,
    timeout: 10_000,
  });

  try {
    // For mso_mdoc signing, we need a P-256 DID (ES256), not Ed25519
    const response = await client.get('/wallet/did?method=key&key_type=p256');
    const dids = response.data.results || [];
    if (dids.length > 0) {
      return dids[0].did;
    }
    return null;
  } catch (err) {
    console.error(`❌ Failed to fetch issuer DID from ${ISSUER_ADMIN_URL}`);
    throw err;
  }
}

async function createCredentialOffer(
  configId: string,
  issuerDid: string,
  credentialSubject: Record<string, any>,
): Promise<string> {
  const client = axios.create({
    baseURL: ISSUER_ADMIN_URL,
    timeout: 10_000,
  });

  // Find the supported_cred_id from the config identifier
  const configs = await getCredentialConfigs();
  const config = configs.find((c: any) => c.identifier === configId);

  if (!config) {
    throw new Error(
      `Credential config '${configId}' not found. Available: ${configs
        .map((c: any) => c.identifier)
        .join(', ')}`,
    );
  }

  try {
    // Create exchange
    // Pass the issuer DID (should be P-256 for mso_mdoc signing)
    const exchangeResponse = await client.post('/oid4vci/exchange/create', {
      supported_cred_id: config.supported_cred_id,
      did: issuerDid,  // ← Issuer's DID (used for MSO signing, not holder binding)
      credential_subject: credentialSubject,
    });

    const exchangeId = exchangeResponse.data.exchange_id;

    // Get offer URL
    const offerResponse = await client.get('/oid4vci/credential-offer', {
      params: { exchange_id: exchangeId },
    });

    return offerResponse.data.credential_offer;
  } catch (err: any) {
    const detail = err?.response?.data?.detail || err?.message || String(err);
    console.error(`❌ Failed to create credential offer: ${detail}`);
    throw err;
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  try {
    const args = parseArgs();

    console.log('📋 Creating mDoc OID4VCI offer...\n');

    // Resolve issuer DID if not provided
    let issuerDid = args.issuerDid;
    if (!issuerDid) {
      console.log('🔍 Fetching issuer DID from ACA-Py...');
      issuerDid = await getIssuerDid();
      if (!issuerDid) {
        console.error('❌ Could not retrieve issuer DID. Use --issuer-did to specify one.');
        process.exit(1);
      }
      console.log(`   DID: ${issuerDid}\n`);
    }

    // Create offer
    console.log('🎫 Creating credential offer...');
    console.log(`   Config ID: ${args.configId}`);
    console.log(`   Subject: ${JSON.stringify(args.subject['org.iso.18013.5.1'])}\n`);

    const offerUrl = await createCredentialOffer(
      args.configId,
      issuerDid,
      args.subject,
    );

    // Output results
    console.log('✅ Credential offer created!\n');
    console.log('═══════════════════════════════════════════════════════════');
    console.log('Offer URL:');
    console.log(offerUrl);
    console.log('═══════════════════════════════════════════════════════════\n');

    // Print wallet setup instructions
    console.log('💡 Next steps:');
    console.log('   1. Open a wallet that supports OID4VCI (e.g., walt.id)');
    console.log('   2. Scan the QR code or paste the offer URL');
    console.log('   3. Accept the credential in your wallet\n');

    // Print curl example
    console.log('📱 Or test via curl:');
    console.log(`   curl "${offerUrl}"\n`);

  } catch (err) {
    process.exit(1);
  }
}

main();
