import { JsonRpcApiProxy, TCPSocketServer } from "json-rpc-api-proxy";
import { OpenID4VCIClientV1_0_13 } from "@sphereon/oid4vci-client";
import { Jwt, ProofOfPossessionCallbacks, Alg } from '@sphereon/oid4vci-common';
import * as jose from 'jose';
import { DIDDocument } from 'did-resolver';

const server = new TCPSocketServer({
  host: process.env.AFJ_HOST || '0.0.0.0',
  port: parseInt(process.env.AFJ_PORT || '3000'),
});
const proxy = new JsonRpcApiProxy(server);

proxy.rpc.addMethod('test', async (): Promise<any> => {
  return {test: 'success'}
})


function jwkToBase64Url(jwk: any): string {
    // Convert the JWK object to a string
    const jsonString = JSON.stringify(jwk);

    // Encode the string to Base64
    const base64String = Buffer.from(jsonString).toString('base64');

    // Make the Base64 string URL-safe
    const base64Url = base64String
        .replace(/\+/g, '-')  // Replace '+' with '-'
        .replace(/\//g, '_')  // Replace '/' with '_'
        .replace(/=+$/, '');  // Remove any '=' padding

    return base64Url;
}

proxy.rpc.addMethod('acceptCredentialOffer', async ({offer}: {offer: string}): Promise<any> => {
  const client = await OpenID4VCIClientV1_0_13.fromURI({
    uri: offer,
    clientId: 'test-clientId', // The clientId if the Authrozation Service requires it.  If a clientId is needed you can defer this also to when the acquireAccessToken method is called
    retrieveServerMetadata: true, // Already retrieve the server metadata. Can also be done afterwards by invoking a method yourself.
  });

  const accessToken = await client.acquireAccessToken();
  console.log(accessToken);

  const { privateKey, publicKey } = await jose.generateKeyPair('ES256');

  // Must be JWS
  async function signCallback(args: Jwt, kid?: string): Promise<string> {
    const jwt = new jose.SignJWT({ ...args.payload })
      .setProtectedHeader({
        alg: args.header.alg,
        typ: 'openid4vci-proof+jwt',
        kid: `did:jwk:${jwkToBase64Url(await jose.exportJWK(publicKey))}#0`
      })
      .setIssuedAt()
      .setExpirationTime('2h')
    if (kid) {
      jwt.setIssuer(kid)
    }
    if (args.payload.aud) {
      jwt.setAudience(args.payload.aud)
    }
    console.log('signing: ', jwt)
    console.log(privateKey)

    return await jwt.sign(privateKey)
  }

  const callbacks: ProofOfPossessionCallbacks<DIDDocument> = {
    signCallback,
  };

  console.log(client.getCredentialEndpoint())
  const credentialResponse = await client.acquireCredentials({
    credentialTypes: 'UniversityDegreeCredential',
    proofCallbacks: callbacks,
    format: 'jwt_vc_json',
    alg: Alg.ES256,
    kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1',
  });
  console.log(credentialResponse.credential);
})

proxy.start()
