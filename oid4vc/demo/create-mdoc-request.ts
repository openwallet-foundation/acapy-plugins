#!/usr/bin/env npx ts-node
/**
 * Create an mDoc OID4VP verification request URL.
 *
 * Usage:
 *   npx ts-node create-mdoc-request.ts [--verifier-url URL] [--fields FIELDS]
 *
 * Examples:
 *   # Use all defaults (given_name, family_name)
 *   npx ts-node create-mdoc-request.ts
 *
 *   # Custom fields to request
 *   npx ts-node create-mdoc-request.ts \\
 *     --fields given_name,family_name,birth_date,document_number
 *
 *   # Specific verifier
 *   npx ts-node create-mdoc-request.ts \\
 *     --verifier-url https://verifier.example.com
 *
 * Environment variables:
 *   ACAPY_VERIFIER_ADMIN_URL - ACA-Py verifier admin URL (default: http://localhost:8031)
 *   ACAPY_VERIFIER_OID4VP_URL - ACA-Py verifier OID4VP public URL (default: http://localhost:8032)
 */

const axios = require('axios');
const { randomUUID } = require('crypto');

// ── Config ────────────────────────────────────────────────────────────────────

const VERIFIER_ADMIN_URL = process.env.ACAPY_VERIFIER_ADMIN_URL || 'http://localhost:8031';
const VERIFIER_OID4VP_URL = process.env.ACAPY_VERIFIER_OID4VP_URL || 'http://localhost:8032';

// Default fields to request from mDL credential
const DEFAULT_FIELDS = ['given_name', 'family_name'];

// ── Argument parsing ──────────────────────────────────────────────────────────

interface Args {
  verifierUrl: string;
  fields: string[];
}

function parseArgs(): Args {
  const args: Args = {
    verifierUrl: VERIFIER_OID4VP_URL,
    fields: DEFAULT_FIELDS,
  };

  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    const next = process.argv[i + 1];

    switch (arg) {
      case '--verifier-url':
        if (next) {
          args.verifierUrl = next;
          i++;
        }
        break;

      case '--fields':
        if (next) {
          args.fields = next.split(',').map((f: string) => f.trim());
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
Create an mDoc OID4VP verification request URL.

Usage:
  npx ts-node create-mdoc-request.ts [OPTIONS]

Options:
  --verifier-url URL      Verifier public URL (default: ${VERIFIER_OID4VP_URL})
  --fields FIELDS         Comma-separated fields to request (default: given_name,family_name)
  --help, -h              Show this help

Examples:
  # Use all defaults
  npx ts-node create-mdoc-request.ts

  # Request additional fields
  npx ts-node create-mdoc-request.ts \\
    --fields given_name,family_name,birth_date,document_number,issue_date,expiry_date

  # Custom verifier
  npx ts-node create-mdoc-request.ts \\
    --verifier-url https://verifier.example.com

Available mDL fields:
  - given_name
  - family_name
  - birth_date
  - issuing_country
  - issuing_authority
  - document_number
  - issue_date
  - expiry_date
  - portrait
  - un_distinguishing_sign
  - driving_privileges

Environment variables:
  ACAPY_VERIFIER_ADMIN_URL   - ACA-Py verifier admin API (default: http://localhost:8031)
  ACAPY_VERIFIER_OID4VP_URL  - ACA-Py verifier OID4VP endpoint (default: http://localhost:8032)
  `);
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function createMdocPresentationRequest(
  verifierAdminUrl: string,
  fields: string[]
): Promise<{ presentationId: string; requestUrl: string }> {
  const client = axios.create({
    baseURL: verifierAdminUrl,
    timeout: 10_000,
  });

  // Build path constraints for the requested fields
  const fieldConstraints = fields.map((field: string) => ({
    path: [`$['org.iso.18013.5.1']['${field}']`],
  }));

  const presentationDefinition = {
    id: randomUUID(),
    format: { mso_mdoc: { alg: ['ES256'] } },
    input_descriptors: [
      {
        id: 'org.iso.18013.5.1.mDL',
        format: { mso_mdoc: { alg: ['ES256'] } },
        constraints: {
          limit_disclosure: 'required',
          fields: fieldConstraints,
        },
      },
    ],
  };

  try {
    // Step 1: Create presentation definition
    const presDefResponse = await client.post('/oid4vp/presentation-definition', {
      pres_def: presentationDefinition,
    });

    const presDefId = presDefResponse.data.pres_def_id;
    if (!presDefId) {
      throw new Error('No pres_def_id returned from /oid4vp/presentation-definition');
    }

    // Step 2: Create request using the presentation definition ID
    const requestResponse = await client.post('/oid4vp/request', {
      pres_def_id: presDefId,
      vp_formats: { mso_mdoc: { alg: ['ES256'] } },
    });

    const presentationId = requestResponse.data.presentation?.presentation_id;
    let requestUrl: string = requestResponse.data.request_uri;

    if (!presentationId || !requestUrl) {
      throw new Error('Missing presentationId or requestUrl in response');
    }

    // OID4VP 1.0 spec (Section 9, Appendix E.8.1) registers `openid4vp` as the
    // wallet invocation scheme. Wallets bind static server metadata to this scheme
    // (Section 13.1.2), including `"authorization_endpoint": "openid4vp:"`.
    // ACA-Py currently returns `openid://` which causes wallets to attempt OIDC
    // discovery and fail with "'authorization_endpoint' is missing". Rewrite the
    // scheme here so wallets receive the correct OID4VP 1.0 URL.
    if (requestUrl.startsWith('openid://')) {
      requestUrl = requestUrl.replace(/^openid:\/\//, 'openid4vp://');
      console.log('[fix] Rewrote scheme: openid:// → openid4vp://');
    }

    return {
      presentationId,
      requestUrl,
    };
  } catch (err: any) {
    const detail = err?.response?.data?.detail || err?.message || String(err);
    console.error(`❌ Failed to create verification request: ${detail}`);
    throw err;
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  try {
    const args = parseArgs();

    console.log('📋 Creating mDoc OID4VP verification request...\n');

    // Create presentation request
    console.log('🎫 Creating verification request...');
    console.log(`   Verifier: ${VERIFIER_ADMIN_URL}`);
    console.log(`   Fields: ${args.fields.join(', ')}\n`);

    const { presentationId, requestUrl } = await createMdocPresentationRequest(
      VERIFIER_ADMIN_URL,
      args.fields
    );

    // Output results
    console.log('✅ Verification request created!\n');
    console.log('═══════════════════════════════════════════════════════════');
    console.log('Presentation ID:');
    console.log(presentationId);
    console.log('\nRequest URL:');
    console.log(requestUrl);
    console.log('═══════════════════════════════════════════════════════════\n');

    // Print wallet setup instructions
    console.log('💡 Next steps:');
    console.log('   1. Share this request URL with a wallet holding an mDL credential');
    console.log('   2. The wallet will present the selected fields');
    console.log('   3. The verifier will validate the presentation\n');

    // Print curl example
    console.log('📱 Or test via curl:');
    console.log(`   curl "${requestUrl}"\n`);

    // Print verification check
    console.log('🔍 Check verification status:');
    console.log(`   curl http://localhost:8031/oid4vp/presentation/${presentationId}\n`);

  } catch (err) {
    process.exit(1);
  }
}

main();
