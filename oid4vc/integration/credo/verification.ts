import express from 'express';
import * as util from 'util';
import { getAgent } from './agent.js';
import { ClaimFormat, MdocRecord } from '@credo-ts/core';
import { logger } from './logger.js';

const router: express.Router = express.Router();

// Present credential to ACA-Py verifier
router.post('/present', async (req: any, res: any) => {
  const agent = getAgent();
  try {

    const { request_uri } = req.body;

    if (!request_uri) {
      return res.status(400).json({
        error: 'request_uri is required'
      });
    }

    console.log('Resolving authorization request:', request_uri);

    const resolvedRequest = await agent!.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(request_uri);

    // Debug logging to understand the resolved request structure
    console.log('📥 Resolved Request Structure:');
    console.log('  - Has dcql:', !!resolvedRequest.dcql);
    console.log('  - Has presentationExchange:', !!resolvedRequest.presentationExchange);
    console.log('  - authorizationRequestPayload keys:', Object.keys(resolvedRequest.authorizationRequestPayload || {}));
    if (resolvedRequest.authorizationRequestPayload) {
        const payload = resolvedRequest.authorizationRequestPayload as any;
        console.log('  - Has dcql_query in payload:', !!payload.dcql_query);
        console.log('  - Has presentation_definition in payload:', !!payload.presentation_definition);
        if (payload.dcql_query) {
            console.log('  - dcql_query structure:', JSON.stringify(payload.dcql_query, null, 2));
        }
    }

    let selectedCredentials: any = undefined;
    let isDcqlRequest = false;
    
    // Check for DCQL query first (OID4VP v1.0 spec)
    if (resolvedRequest.dcql) {
        isDcqlRequest = true;
        const { queryResult } = resolvedRequest.dcql;
        
        console.log('📋 DCQL Query Details:');
        console.log('  - Can be satisfied:', queryResult.can_be_satisfied);
        console.log('  - Credentials:', JSON.stringify(queryResult.credentials, null, 2));
        
        if (queryResult.can_be_satisfied) {
            // Use Credo's built-in DCQL credential selection
            selectedCredentials = agent!.openid4vc.holder.selectCredentialsForDcqlRequest(queryResult);
            console.log('✅ Using Credo selectCredentialsForDcqlRequest');
            console.log('Selected credentials keys:', Object.keys(selectedCredentials));
        } else {
            console.log('⚠️ DCQL query cannot be satisfied with available credentials');
            return res.status(400).json({ error: 'DCQL query cannot be satisfied with available credentials' });
        }
    } else if (resolvedRequest.presentationExchange) {
        const { credentialsForRequest } = resolvedRequest.presentationExchange;
        
        // DEBUG: Print presentation definition to confirm intent_to_retain is preserved
        const debugPd = (resolvedRequest.presentationExchange as any).definition ?? 
                        resolvedRequest.authorizationRequestPayload?.presentation_definition;
        if (debugPd) {
            console.log('📝 PD input_descriptors[0].constraints.fields (first 3):');
            try {
                const fields = debugPd.input_descriptors?.[0]?.constraints?.fields?.slice(0, 3);
                console.log(JSON.stringify(fields, null, 2));
            } catch (e) { console.log('⚠️ Could not print PD fields:', e); }
        }
        
        console.log('📋 Presentation Exchange Details:');
        console.log('  - Requirements satisfied:', credentialsForRequest.areRequirementsSatisfied);
        console.log('  - Requirements:', JSON.stringify(credentialsForRequest.requirements, null, 2));
        
        if (credentialsForRequest.areRequirementsSatisfied) {
            // Use Credo's built-in credential selection - this returns credentials in the correct format
            selectedCredentials = agent!.openid4vc.holder.selectCredentialsForPresentationExchangeRequest(credentialsForRequest);
            console.log('✅ Using Credo selectCredentialsForPresentationExchangeRequest');
            console.log('Selected credentials keys:', Object.keys(selectedCredentials));
        } else {
            // If requirements not satisfied, attempt manual lookup and format credentials properly
            console.log('⚠️ Requirements not satisfied automatically. Attempting manual credential lookup...');
            
            // Fetch all mdoc records
            let mdocRecords: MdocRecord[] = [];
            if (agent?.mdoc) {
                mdocRecords = await agent!.mdoc.getAll();
            }
            console.log(`Found ${mdocRecords.length} mdoc credentials in storage`);
            
            if (mdocRecords.length > 0) {
                // Use firstCredential.docType to get the docType
                const firstMdoc = mdocRecords[0].firstCredential;
                console.log('🔍 First Mdoc Record type:', mdocRecords[0].type);
                console.log('🔍 First Mdoc Record docType:', firstMdoc.docType);
                
                // Build credentials in the format expected by acceptOpenId4VpAuthorizationRequest
                // Format: DifPexInputDescriptorToCredentials = Record<string, SubmissionEntryCredential[]>
                selectedCredentials = {};
                
                for (const requirement of credentialsForRequest.requirements) {
                    for (const submission of requirement.submissionEntry) {
                        if (!selectedCredentials[submission.inputDescriptorId]) {
                            selectedCredentials[submission.inputDescriptorId] = [];
                        }
                        
                        // For mdoc credentials, we need to format them as SubmissionEntryCredential
                        for (const mdocRecord of mdocRecords) {
                            // Check if this mdoc matches the input descriptor (by docType)
                            const inputDescriptorId = submission.inputDescriptorId;
                            const mdocDocType = mdocRecord.firstCredential.docType;
                            console.log(`Checking mdoc docType ${mdocDocType} against inputDescriptorId ${inputDescriptorId}`);
                            
                            // Create properly formatted SubmissionEntryCredential for mdoc
                            selectedCredentials[submission.inputDescriptorId].push({
                                claimFormat: ClaimFormat.MsoMdoc,
                                credentialRecord: mdocRecord,
                                disclosedPayload: {} // Empty - Credo will compute based on constraints
                            });
                        }
                    }
                }
            }
            
            if (!selectedCredentials || Object.keys(selectedCredentials).length === 0) {
                return res.status(400).json({ error: 'Could not find the required credentials for the presentation submission' });
            }
        }
    }

    if (!selectedCredentials) {
        return res.status(400).json({ error: 'No credentials selected for presentation (no DCQL or presentationExchange in request)' });
    }

    // Use Credo's OpenID4VC module to handle the presentation
    console.log('Submitting presentation...');

    console.log('DEBUG: Selected credentials keys:', Object.keys(selectedCredentials));
    for (const key in selectedCredentials) {
        console.log(`DEBUG: Credentials for ${key}:`, selectedCredentials[key].length);
        selectedCredentials[key].forEach((c: any, i: number) => {
             console.log(`DEBUG: Credential ${i} claimFormat:`, c?.claimFormat);
             console.log(`DEBUG: Credential ${i} credentialRecord type:`, c?.credentialRecord?.constructor?.name);
        });
    }

    // Build the accept request based on whether this is DCQL or PEX
    const acceptRequest: any = {
        authorizationRequestPayload: resolvedRequest.authorizationRequestPayload,
    };
    
    if (isDcqlRequest && resolvedRequest.dcql) {
        acceptRequest.dcql = { credentials: selectedCredentials };
        console.log('DEBUG: Using DCQL response format');
    } else if (resolvedRequest.presentationExchange) {
        acceptRequest.presentationExchange = { credentials: selectedCredentials };
        console.log('DEBUG: Using PresentationExchange response format');
    }
    
    const submissionResult = await agent!.openid4vc.holder.acceptOpenId4VpAuthorizationRequest(acceptRequest);

    console.log('✅ Presentation submitted successfully');
    
    // Inspect the result to avoid serialization errors
    const safeResult: any = {};
    
    if (submissionResult.submittedResponse) {
        console.log('Submitted response keys:', Object.keys(submissionResult.submittedResponse));
        safeResult.submittedResponse = submissionResult.submittedResponse;
    }
    
    if (submissionResult.serverResponse) {
        const sRes = submissionResult.serverResponse;
        console.log('Server response constructor:', sRes.constructor ? sRes.constructor.name : typeof sRes);
        
        // If it looks like a Response object (node-fetch/undici), extract useful info
        if (sRes.status !== undefined) {
             safeResult.serverResponse = {
                 status: sRes.status,
                 statusText: sRes.statusText,
                 // body might be a stream or already consumed, so be careful
             };
             
             // Try to get JSON if possible and not consumed
             try {
                 if (typeof sRes.clone === 'function') {
                     const clone = sRes.clone();
                     if (typeof clone.json === 'function') {
                         safeResult.serverResponse.body = await clone.json();
                     }
                 } else if (sRes.bodyUsed === false && typeof sRes.json === 'function') {
                      safeResult.serverResponse.body = await sRes.json();
                 } else if (typeof sRes.data === 'object') {
                      // Axios style?
                      safeResult.serverResponse.body = sRes.data;
                 }
             } catch (e) {
                 console.log('Could not read server response body:', e);
             }
        } else {
            // Assume it's a plain object or something safe
            try {
                JSON.stringify(sRes);
                safeResult.serverResponse = sRes;
            } catch (e) {
                console.log('⚠️ serverResponse is not JSON serializable:', e);
                safeResult.serverResponse = {
                    error: 'Response not serializable',
                    preview: util.inspect(sRes, { depth: 2 })
                };
            }
        }
    }

    try {
        res.json({
            success: true,
            presentation_submission: safeResult.submittedResponse, // Ensure this is at top level for test check
            result: safeResult,
            request_uri: request_uri
        });
    } catch (jsonError) {
        console.error('Error sending JSON response:', jsonError);
        res.status(500).json({
            error: 'Failed to serialize response',
            details: String(jsonError)
        });
    }

  } catch (error) {
    console.error('Error presenting credentials:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;

    res.status(500).json({
      error: 'Failed to present credentials',
      details: errorMessage,
      stack: errorStack
    });
  }
});

export default router;
