/**
 * Simplified Credo OID4VC Agent
 * 
 * This service acts as a holder/verifier that can:
 * - Receive credentials from ACA-Py OID4VCI issuer  
 * - Present credentials to ACA-Py OID4VP verifier
 * 
 * Supports both mso_mdoc and SD-JWT credential formats.
 */

// IMPORTANT: Import askar-nodejs first to register the native bindings
// before any credo-ts packages that depend on @openwallet-foundation/askar-shared
import '@openwallet-foundation/askar-nodejs';

import express from 'express';
import issuanceRouter from './issuance.js';
import verificationRouter from './verification.js';
import debugRouter from './debug.js';
import { initializeAgent, addTrustedCertificate, setTrustedCertificates, getTrustedCertificates } from './agent.js';
import { logger } from './logger.js';

const app = express();
const PORT = parseInt(process.env.PORT || '3020', 10);

// Middleware
app.use(express.json());
app.use((req: any, res: any, next: any) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }
  next();
});

// Health check endpoint
app.get('/health', (req: any, res: any) => {
  res.status(200).json({
    status: 'healthy',
    service: 'credo-oid4vc-agent',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// Trust Anchor Management API
// ============================================================================

/**
 * POST /x509/trust-anchors
 * Add a trusted certificate to the X509 module
 * 
 * Request body:
 * {
 *   "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
 * }
 */
app.post('/x509/trust-anchors', (req: any, res: any) => {
  try {
    const { certificate_pem } = req.body;
    
    if (!certificate_pem) {
      return res.status(400).json({ 
        error: 'certificate_pem is required' 
      });
    }
    
    addTrustedCertificate(certificate_pem);
    
    res.status(201).json({
      status: 'success',
      message: 'Trust anchor added successfully'
    });
  } catch (error: any) {
    logger.error('Error adding trust anchor:', error);
    res.status(500).json({ 
      error: 'Failed to add trust anchor',
      details: error.message 
    });
  }
});

/**
 * PUT /x509/trust-anchors
 * Replace all trusted certificates with new set
 * 
 * Request body:
 * {
 *   "certificates": ["-----BEGIN CERTIFICATE-----\n...", ...]
 * }
 */
app.put('/x509/trust-anchors', (req: any, res: any) => {
  try {
    const { certificates } = req.body;
    
    if (!Array.isArray(certificates)) {
      return res.status(400).json({ 
        error: 'certificates array is required' 
      });
    }
    
    setTrustedCertificates(certificates);
    
    res.json({
      status: 'success',
      message: `Set ${certificates.length} trusted certificates`,
      count: certificates.length
    });
  } catch (error: any) {
    logger.error('Error setting trust anchors:', error);
    res.status(500).json({ 
      error: 'Failed to set trust anchors',
      details: error.message 
    });
  }
});

/**
 * GET /x509/trust-anchors
 * Get list of currently trusted certificates
 */
app.get('/x509/trust-anchors', (req: any, res: any) => {
  try {
    const certificates = getTrustedCertificates();
    
    res.json({
      status: 'success',
      count: certificates.length,
      certificates
    });
  } catch (error: any) {
    logger.error('Error getting trust anchors:', error);
    res.status(500).json({ 
      error: 'Failed to get trust anchors',
      details: error.message 
    });
  }
});

// Mount routers
app.use('/oid4vci', issuanceRouter);
app.use('/oid4vp', verificationRouter);
app.use('/debug', debugRouter);

// Start server
const startServer = async () => {
  try {
    await initializeAgent(PORT);
    
    app.listen(PORT, '0.0.0.0', () => {
      logger.info(`🚀 Credo OID4VC Agent running on port ${PORT}`);
      logger.info(`📋 Health check: http://localhost:${PORT}/health`);
      logger.info(`🎫 Accept credentials: POST http://localhost:${PORT}/oid4vci/accept-offer`);
      logger.info(`📤 Present credentials: POST http://localhost:${PORT}/oid4vp/present`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer().catch(logger.error);
