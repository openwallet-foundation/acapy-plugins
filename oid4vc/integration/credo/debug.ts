/**
 * Debug routes for isolating integration test failures.
 *
 * These endpoints expose internal Credo record structures that are not
 * visible from the standard /oid4vci/accept-offer response, giving us
 * exact knowledge of what Credo returns from requestCredentials() for
 * each credential format.
 *
 * Intended for use by targeted integration tests only — not production use.
 */

import express from 'express';
import { getAgent } from './agent.js';

const router: express.Router = express.Router();

// ---------------------------------------------------------------------------
// Helper: deep-inspect a single credential record returned by Credo
// ---------------------------------------------------------------------------

function inspectRecord(record: any): Record<string, unknown> {
  const info: Record<string, unknown> = {
    constructor_name: record?.constructor?.name ?? null,
    record_type: record?.type ?? null,
    own_keys: record ? Object.keys(record) : [],
    prototype_keys: record
      ? Object.getOwnPropertyNames(Object.getPrototypeOf(record))
      : [],
  };

  // credentialInstances (W3cCredentialRecord, SdJwtVcRecord, MdocRecord)
  const instances: any[] = record?.credentialInstances ?? [];
  info.credential_instances_count = instances.length;
  info.credential_instances = instances.map((inst: any) => {
    const entry: Record<string, unknown> = { own_keys: Object.keys(inst) };
    for (const [k, v] of Object.entries(inst)) {
      if (typeof v === 'string') {
        entry[k] = (v as string).length > 100
          ? (v as string).substring(0, 100) + '…'
          : v;
      } else if (v === null || v === undefined) {
        entry[k] = v;
      } else if (typeof v === 'object') {
        entry[k] = { type: (v as any)?.constructor?.name, keys: Object.keys(v as any) };
      } else {
        entry[k] = typeof v;
      }
    }
    // Also probe well-known getter/prototype properties not exposed by Object.entries.
    // In Credo 0.6.x, W3cJwtVerifiableCredential stores the JWT behind a getter
    // (serializedJwt), not as an own enumerable property.
    for (const gkey of [
      'serializedJwt', 'compactJwtVc', 'jwt', 'encoded',
      'issuerSignedBase64Url', 'compactSdJwtVc',
    ]) {
      if (gkey in entry) continue; // already captured by Object.entries
      try {
        const gval = (inst as any)[gkey];
        if (gval === undefined || gval === null) continue;
        if (typeof gval === 'string') {
          entry[gkey] = gval.length > 100 ? gval.substring(0, 100) + '…' : gval;
        } else if (typeof gval === 'object') {
          entry[gkey] = { type: (gval as any)?.constructor?.name, keys: Object.keys(gval as any).slice(0, 10) };
        }
      } catch (_) { /* getter may throw; ignore */ }
    }
    // Deep-drill: in Credo 0.6.x W3cJwtVerifiableCredential, the compact JWT is in
    // inst.jwt.serializedJwt (inst.jwt is a Jwt parse object, not a string).
    // Expose it directly so tests can find it without multi-level traversal.
    try {
      const jwtObj = (inst as any).jwt;
      if (jwtObj && typeof jwtObj === 'object') {
        for (const k of ['serializedJwt', 'compact', 'encoded']) {
          const v = (jwtObj as any)[k];
          if (typeof v === 'string' && v.length > 0) {
            entry[`jwt_${k}`] = v.length > 100 ? v.substring(0, 100) + '…' : v;
            break;
          }
        }
      }
    } catch (_) { /* ignore */ }
    // Deep-drill: credentialInstances[0] may be a wrapper { credential: W3cJwtVerifiableCredential }
    // where inst.credential.jwt.serializedJwt is the compact JWT string.
    try {
      const credObj = (inst as any).credential;
      if (credObj && typeof credObj === 'object') {
        const jwtObj = (credObj as any).jwt;
        if (jwtObj && typeof jwtObj === 'object') {
          for (const k of ['serializedJwt', 'compact', 'encoded']) {
            const v = (jwtObj as any)[k];
            if (typeof v === 'string' && v.length > 0) {
              entry[`credential_jwt_${k}`] = v.length > 100 ? v.substring(0, 100) + '…' : v;
              break;
            }
          }
        }
      }
    } catch (_) { /* ignore */ }
    return entry;
  });

  // Test well-known getters / properties
  const getterMap: Record<string, unknown> = {};
  for (const key of [
    'encoded', 'firstCredential', 'credential', 'type',
    'claimFormat', 'jwt', 'serializedJwt', 'compact', 'base64Url',
  ]) {
    try {
      const val = (record as any)[key];
      if (val === undefined) {
        getterMap[key] = '__undefined__';
      } else if (typeof val === 'string') {
        getterMap[key] = val.length > 100 ? val.substring(0, 100) + '…' : val;
      } else if (val === null) {
        getterMap[key] = null;
      } else if (typeof val === 'object') {
        getterMap[key] = {
          type: (val as any)?.constructor?.name,
          keys: Object.keys(val as any).slice(0, 20),
        };
      } else {
        getterMap[key] = `${typeof val}: ${val}`;
      }
    } catch (e: any) {
      getterMap[key] = `ERROR: ${e?.message}`;
    }
  }
  info.getters = getterMap;

  // Deep-drill for W3cCredentialRecord: record.firstCredential.jwt.serializedJwt
  // In Credo 0.6.x this is the only path to the compact JWT string.
  try {
    const fc = (record as any).firstCredential;
    if (fc && typeof fc === 'object') {
      const fcJwt = (fc as any).jwt;
      if (fcJwt && typeof fcJwt === 'object') {
        for (const k of ['serializedJwt', 'compact', 'encoded']) {
          const v = (fcJwt as any)[k];
          if (typeof v === 'string' && v.length > 0) {
            info.w3c_serialized_jwt = v.length > 100 ? v.substring(0, 100) + '…' : v;
            break;
          }
        }
      }
    }
  } catch (_) { /* ignore */ }

  // Probe record._credential (private backing field, bypasses Credo's '***' masking).
  // In Credo 0.6.x this is the path used by issuance.ts Attempt 5.
  try {
    const raw = (record as any)._credential;
    if (typeof raw === 'string' && raw.startsWith('ey') && raw.includes('.')) {
      info.record_credential_raw = raw.length > 100 ? raw.substring(0, 100) + '…' : raw;
    } else if (typeof raw === 'string' && raw.length > 0) {
      // Might be JSON-encoded — try to extract jwt/serializedJwt
      try {
        const parsed = JSON.parse(raw);
        for (const k of ['jwt', 'serializedJwt', 'encoded']) {
          const v = (parsed as any)[k];
          if (typeof v === 'string' && v.startsWith('ey') && v.includes('.')) {
            info.record_credential_raw = v.length > 100 ? v.substring(0, 100) + '…' : v;
            break;
          }
        }
      } catch (_) { /* not JSON */ }
    }
  } catch (_) { /* ignore */ }

  // What does JSON.stringify see?
  try {
    const plain = JSON.parse(JSON.stringify(record));
    info.serialized_keys = Object.keys(plain);
    const plainInstances: any[] = plain?.credentialInstances ?? [];
    info.serialized_instances = plainInstances.map((inst: any) => ({
      keys: Object.keys(inst),
      credential_preview: typeof inst.credential === 'string'
        ? inst.credential.substring(0, 100)
        : JSON.stringify(inst.credential)?.substring(0, 80),
    }));
  } catch (e: any) {
    info.serialize_error = e?.message;
  }

  return info;
}

// ---------------------------------------------------------------------------
// POST /debug/resolve-offer
//
// Resolve a credential offer and return the offer metadata, so we can see
// exactly what formats and binding methods the issuer advertises.
// ---------------------------------------------------------------------------

router.post('/resolve-offer', async (req: any, res: any) => {
  const agent = getAgent();
  try {
    const { credential_offer } = req.body;
    if (!credential_offer) {
      return res.status(400).json({ error: 'credential_offer is required' });
    }

    const resolved = await agent!.openid4vc.holder.resolveCredentialOffer(
      typeof credential_offer === 'string'
        ? credential_offer
        : `openid-credential-offer://?credential_offer=${encodeURIComponent(
            JSON.stringify(credential_offer)
          )}`
    );

    const configs: Record<string, unknown> = {};
    for (const [id, config] of Object.entries(
      resolved.offeredCredentialConfigurations
    )) {
      const c = config as any;
      configs[id] = {
        format: c.format,
        cryptographic_binding_methods_supported:
          c.cryptographic_binding_methods_supported,
        proof_types_supported: c.proof_types_supported,
        scope: c.scope,
      };
    }

    res.json({
      credential_issuer:
        resolved.metadata?.credentialIssuer?.credential_issuer,
      draft_version: (resolved.metadata as any)?.originalDraftVersion,
      offered_configurations: configs,
    });
  } catch (error: any) {
    res.status(500).json({
      error: 'Resolve failed',
      details: error?.message || String(error),
    });
  }
});

// ---------------------------------------------------------------------------
// POST /debug/accept-offer-inspect
//
// Run the full requestCredentials() flow for a credential offer and return
// a deep inspection of every returned record — without trying to extract a
// "nice" credential value.  The response shows exactly what keys/values each
// record exposes so we can write correct extraction code (or a targeted fix).
//
// Also captures the binding resolver input so we can see the credentialFormat
// and proofTypes that Credo passes us.
// ---------------------------------------------------------------------------

router.post('/accept-offer-inspect', async (req: any, res: any) => {
  const agent = getAgent();
  try {
    const { credential_offer } = req.body;
    if (!credential_offer) {
      return res.status(400).json({ error: 'credential_offer is required' });
    }

    const resolvedOffer = await agent!.openid4vc.holder.resolveCredentialOffer(
      typeof credential_offer === 'string'
        ? credential_offer
        : `openid-credential-offer://?credential_offer=${encodeURIComponent(
            JSON.stringify(credential_offer)
          )}`
    );

    // Capture what the binding resolver is called with
    const bindingResolverCalls: any[] = [];

    const credentialBindingResolver = async (opts: any) => {
      const { proofTypes, credentialFormat, supportsJwk, supportsAllDidMethods,
              supportedDidMethods } = opts;
      const call: any = {
        credentialFormat,
        supportsJwk,
        supportsAllDidMethods,
        supportedDidMethods,
        proof_type_algs: proofTypes?.jwt?.supportedSignatureAlgorithms,
      };

      let algorithm: string = 'EdDSA';
      if (credentialFormat === 'mso_mdoc') {
        algorithm = 'ES256';
      } else if (proofTypes?.jwt?.supportedSignatureAlgorithms?.[0]) {
        algorithm = proofTypes.jwt.supportedSignatureAlgorithms[0];
      }

      // Credo 0.6.x throws for JWK binding on W3C credential formats (jwt_vc_json,
      // jwt_vc_json-ld, ldp_vc). Use did:key binding for those; JWK for others.
      // ACA-Py's key_material_for_kid() now handles the Multikey VM type that
      // Credo 0.6.x did:key documents use.
      const W3C_FORMATS = ['jwt_vc_json', 'jwt_vc_json-ld', 'ldp_vc'];
      if (W3C_FORMATS.includes(credentialFormat)) {
        const algStr2 = algorithm as string;
        const kmsKeyType2 = algStr2 === 'ES256'
          ? { kty: 'EC' as const, crv: 'P-256' as const }
          : { kty: 'OKP' as const, crv: 'Ed25519' as const };
        try {
          const w3cKey = await agent!.kms.createKey({ type: kmsKeyType2 });
          const didResult = await agent!.dids.create({ method: 'key', options: { keyId: w3cKey.keyId } });
          const didState = (didResult.didState as any);
          if (didState.state !== 'finished') {
            throw new Error(`did:key creation failed: ${JSON.stringify(didState)}`);
          }
          const verificationMethodId =
            didState.didDocument?.verificationMethod?.[0]?.id ?? didState.did;
          call.resolved_method = 'did';
          call.resolved_algorithm = algorithm;
          bindingResolverCalls.push(call);
          return { method: 'did', didUrls: [verificationMethodId] };
        } catch (e) {
          call.resolved_method = 'did:key_error';
          call.resolved_algorithm = algorithm;
          bindingResolverCalls.push(call);
          throw e;
        }
      }

      const algStr = algorithm;
      const keyType =
        algStr === 'ES256' ? { kty: 'EC' as const, crv: 'P-256' as const }
        : algStr === 'ES384' ? { kty: 'EC' as const, crv: 'P-384' as const }
        : algStr === 'ES256K' ? { kty: 'EC' as const, crv: 'secp256k1' as const }
        : { kty: 'OKP' as const, crv: 'Ed25519' as const };

      const key = await agent!.kms.createKey({ type: keyType });
      const { Kms } = await import('@credo-ts/core');
      const publicJwk = Kms.PublicJwk.fromPublicJwk(key.publicJwk);

      call.resolved_method = 'jwk';
      call.resolved_algorithm = algorithm;
      bindingResolverCalls.push(call);

      return { method: 'jwk', keys: [publicJwk] };
    };

    const tokenResponse = await agent!.openid4vc.holder.requestToken({
      resolvedCredentialOffer: resolvedOffer,
    });

    let credentialResponse: any = null;
    let requestError: string | null = null;
    let requestErrorStack: string | null = null;
    try {
      credentialResponse = await agent!.openid4vc.holder.requestCredentials({
        resolvedCredentialOffer: resolvedOffer,
        ...tokenResponse,
        credentialBindingResolver,
      });
    } catch (e: any) {
      requestError = e?.message || String(e);
      requestErrorStack = e?.stack ?? null;
    }

    const result: Record<string, unknown> = {
      binding_resolver_calls: bindingResolverCalls,
      request_error: requestError,
      request_error_stack: requestErrorStack,
      credentials_count: credentialResponse?.credentials?.length ?? 0,
      deferred_count: credentialResponse?.deferredCredentials?.length ?? 0,
      credentials: (credentialResponse?.credentials ?? []).map((item: any) => {
        const inspection = inspectRecord(item.record);
        // Also expose item.credential — the raw credential value from the OID4VCI
        // response (before storage). In Credo 0.6.x this is the compact JWT string
        // for jwt_vc_json (issuance.ts Attempt 0 uses this path).
        const rawCred = item.credential;
        if (typeof rawCred === 'string' && rawCred.length > 0) {
          (inspection as any)['raw_oidc_credential'] =
            rawCred.length > 100 ? rawCred.substring(0, 100) + '…' : rawCred;
        }
        return inspection;
      }),
    };

    res.json(result);
  } catch (error: any) {
    res.status(500).json({
      error: 'Inspection failed',
      details: error?.message || String(error),
      stack: error?.stack,
    });
  }
});

export default router;
