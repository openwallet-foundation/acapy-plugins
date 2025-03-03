import express from "express";

import axios from "axios";

import { v4 as uuidv4 } from "uuid";
import {default as NodeCache } from "node-cache";
import QRCode from "qrcode-svg";

import path from "node:path";

import pino from "pino";
import colada from "pino-colada";

import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { EventEmitter } from 'node:events';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ##        #######   ######    ######   ######## ########
// ##       ##     ## ##    ##  ##    ##  ##       ##     ##
// ##       ##     ## ##        ##        ##       ##     ##
// ##       ##     ## ##   #### ##   #### ######   ########
// ##       ##     ## ##    ##  ##    ##  ##       ##   ##
// ##       ##     ## ##    ##  ##    ##  ##       ##    ##
// ########  #######   ######    ######   ######## ##     ##
// Setup the Pino Logger

const logger_stream = {
  formatter: colada(),
  console: (level, msg) => {
    if (level <= 30)
      process.stdout.write(msg);
    else
      process.stderr.write(msg);
  },
  write: function(msg) {
    msg = JSON.parse(msg);
    let level = msg["level"] ?? 30;
    msg = this.formatter(msg);
    if (msg.length > 0) {
      this.console(level, msg);
    }
  },
}

const logger = pino({
  prettifier: colada,
  level: 'trace',
}, logger_stream);

// ######## ##     ## ########  ########  ########  ######   ######
// ##        ##   ##  ##     ## ##     ## ##       ##    ## ##    ##
// ##         ## ##   ##     ## ##     ## ##       ##       ##
// ######      ###    ########  ########  ######    ######   ######
// ##         ## ##   ##        ##   ##   ##             ##       ##
// ##        ##   ##  ##        ##    ##  ##       ##    ## ##    ##
// ######## ##     ## ##        ##     ## ########  ######   ######
// Setup the Express app

const app = express();
app.set("views", path.join(__dirname, "templates"));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
app.use(express.json());
app.use(express.static("public"));

const events = new EventEmitter();
const exchangeCache = new NodeCache({ stdTTL: 300, checkperiod: 400 });
const presentationCache = new NodeCache({ stdTTL: 300, checkperiod: 400 });

const API_BASE_URL = process.env.API_BASE_URL || "http://localhost:3001";
const API_KEY = process.env.API_KEY;
let jwtVcSupportedCredCreated = false;
let sdJwtSupportedCredCreated = false;
let jwtVcSupportedCredID = "";
let sdJwtSupportedCredID = "";


//    ###     ######     ###            ########  ##    ##
//   ## ##   ##    ##   ## ##           ##     ##  ##  ##
//  ##   ##  ##        ##   ##          ##     ##   ####
// ##     ## ##       ##     ## ####### ########     ##
// ######### ##       #########         ##           ##
// ##     ## ##    ## ##     ##         ##           ##
// ##     ##  ######  ##     ##         ##           ##
// ACA-Py related controller helper functions

// Begin Issue JWT Credential Flow
async function issue_jwt_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received credential data from user."});

  const { fname: firstName, lname: lastName, email } = req.body

  const headers = {
    accept: "application/json",
  };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create credential schema
  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create/jwt`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      cryptographic_binding_methods_supported: ["did"],
      cryptographic_suites_supported: ["ES256"],
      display: [
        {
          name: "University Credential",
          locale: "en-US",
          logo: {
            url: "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
            alt_text: "a square logo of a university",
          },
          background_color: "#12107c",
          text_color: "#FFFFFF",
        },
      ],
      format: "jwt_vc_json",
      credentialSubject: {
        degree: {},
        given_name: {
          display: [
            {
              name: "Given Name",
              locale: "en-US",
            },
          ],
        },
        gpa: {
          display: [
            {
              name: "GPA",
            },
          ],
        },
        last_name: {
          display: [
            {
              name: "Surname",
              locale: "en-US",
            },
          ],
        },
      },
      type: ["VerifiableCredential", "UniversityDegreeCredential"],
      id: "UniversityDegreeCredential",
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
      ]
    }),
  };

  if (!jwtVcSupportedCredCreated){
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    jwtVcSupportedCredID = supportedCredentialData.supported_cred_id;
    jwtVcSupportedCredCreated = true;
  }
  



  // Create DID for issuance
  const createDidUrl = `${API_BASE_URL}/did/jwk/create`;
  const createDidOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      key_type: "p256",
    }),
  };

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Creating DID."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create DID Request to: ${createDidUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createDidOptions});
  const didData = await fetchApiData(createDidUrl, createDidOptions);
  const { did } = didData;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Created DID: ${did}`});
  logger.info(did);
  logger.info(jwtVcSupportedCredID);


  // Create Credential Exchange records
  const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
  const exchangeCreateOptions = {
    credential_subject: { id: req.body.registrationId, first_name: firstName, last_name: lastName, email },
    verification_method: did+"#0",
    supported_cred_id: jwtVcSupportedCredID,
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
  const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions);
  const exchangeId = exchangeResponse.data.exchange_id;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});


  // Get Credential Offer information
  const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
  const queryParams = {
    user_pin_required: false,
    exchange_id: exchangeId,
  };
  const credentialOfferOptions = {
    params: queryParams,
    headers: headers,
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
  const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
  const credentialOffer = offerResponse.data;

  // Generate QRCode and send it to the browser via HTMX events
  logger.info(JSON.stringify(offerResponse.data));
  logger.info(exchangeId);
  
  let qrcode;
  if (credentialOffer.hasOwnProperty("credential_offer")) {
    // credential offer is passed by value
    qrcode = credentialOffer.credential_offer
  } else {
    // credential offer is passed by reference, and the wallet must dereference it using the
    // /oid4vci/dereference-credential-offer endpoint
    qrcode = credentialOffer.credential_offer_uri
  }

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
  exchangeCache.set(exchangeId, { exchangeId, credentialOffer, did, jwtVcSupportedCredID, registrationId: req.body.registrationId });

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
}


// Begin Issue SD-JWT Credential Flow
async function issue_sdjwt_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received credential data from user."});

  const { fname: firstName, lname: lastName, age: ageString } = req.body
  const age = parseInt(ageString);

  const headers = {
    accept: "application/json",
  };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create credential schema
  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      format: "vc+sd-jwt",
      id: "IDCard",
      format_data: {
        cryptographic_binding_methods_supported: ["jwk"],
        display: [
          {
            "name": "ID Card",
            "locale": "en-US",
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ],
        vct: "ExampleIDCard",
        "claims": {
          "given_name": {
            "mandatory": true,
            "value_type": "string",
          },
          "family_name": {
            "mandatory": true,
            "value_type": "string",
          },
          "something_nested": {
            "key1": {
              "key2": {
                "key3": {
                  "mandatory": true,
                  "value_type": "string",
                },
              },
            },
          },
          "age_equal_or_over": {
            "12": {
              "mandatory": true,
              "value_type": "boolean",
            },
            "14": {
              "mandatory": true,
              "value_type": "boolean",
            },
            "16": {
              "mandatory": true,
              "value_type": "boolean",
            },
            "18": {
              "mandatory": true,
              "value_type": "boolean",
            },
            "21": {
              "mandatory": true,
              "value_type": "boolean",
            },
            "65": {
              "mandatory": true,
              "value_type": "boolean",
            },
          }
        },
      },
      vc_additional_data: {
        sd_list: [
          "/given_name",
          "/family_name",
          "/age_equal_or_over/12",
          "/age_equal_or_over/14",
          "/age_equal_or_over/16",
          "/age_equal_or_over/18",
          "/age_equal_or_over/21",
          "/age_equal_or_over/65"
        ]
      }
    }),
  };

  if (!sdJwtSupportedCredCreated){

    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    sdJwtSupportedCredID = supportedCredentialData.supported_cred_id;
    sdJwtSupportedCredCreated = true;
  }


  // Create DID for issuance
  const createDidUrl = `${API_BASE_URL}/did/jwk/create`;
  const createDidOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      key_type: "p256",
    }),
  };

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Creating DID."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create DID Request to: ${createDidUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createDidOptions});
  const didData = await fetchApiData(createDidUrl, createDidOptions);
  const { did } = didData;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Created DID: ${did}`});
  logger.info(did);
  logger.info(sdJwtSupportedCredID);


  // Create Credential Exchange records
  const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
  const exchangeCreateOptions = {
    did: did,
    verification_method: did+"#0",
    supported_cred_id: sdJwtSupportedCredID,
    credential_subject: {
      given_name: firstName,
      family_name: lastName,
      something_nested: {key1: {key2: {key3: "something nested"}}},
      source_document_type: "id_card",
      age_equal_or_over: {
        "12": age >= 12,
        "14": age >= 14,
        "16": age >= 16,
        "18": age >= 18,
        "21": age >= 21,
        "65": age >= 65,
      }
    },
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
  const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions);
  const exchangeId = exchangeResponse.data.exchange_id;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});


  // Get Credential Offer information
  const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
  const queryParams = {
    user_pin_required: false,
    exchange_id: exchangeId,
  };
  const credentialOfferOptions = {
    params: queryParams,
    headers: headers,
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
  const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
  const credentialOffer = offerResponse.data;

  // Generate QRCode and send it to the browser via HTMX events
  logger.info(JSON.stringify(offerResponse.data));
  logger.info(exchangeId);

  let qrcode;
  if (credentialOffer.hasOwnProperty("credential_offer")) {
    // credential offer is passed by value
    qrcode = credentialOffer.credential_offer
  } else {
    // credential offer is passed by reference, and the wallet must dereference it using the
    // /oid4vci/dereference-credential-offer endpoint
    qrcode = credentialOffer.credential_offer_uri
  }

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
  exchangeCache.set(exchangeId, { exchangeId, credentialOffer, did, sdJwtSupportedCredID, registrationId: req.body.registrationId });

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
}


// Begin JWT VC JSON Presentation Flow
async function create_jwt_vc_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create Presentation Definition
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating Presentation Definition."});
  const presentationDefinition = {"pres_def": {
    "id": uuidv4(),
    "purpose": "Present basic profile info",
    "format": {
      "jwt_vc_json": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vp_json": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vc": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vp": {
        "alg": [
          "ES256"
        ]
      }
    },
    "input_descriptors": [
      {
        "id": "4ce7aff1-0234-4f35-9d21-251668a60950",
        "name": "Profile",
        "purpose": "Present basic profile info",
        "constraints": {
          "fields": [
            {
              "name": "name",
              "path": [
                "$.vc.credentialSubject.first_name",
                "$.credentialSubject.first_name"
              ],
              "filter": {
                "type": "string",
                "pattern": "^.{1,64}$"
              }
            },
            {
              "name": "lastname",
              "path": [
                "$.vc.credentialSubject.last_name",
                "$.credentialSubject.last_name"
              ],
              "filter": {
                "type": "string",
                "pattern": "^.{1,64}$"
              }
            }
          ]
        }
      }
    ]
  }
  };

  const presentationDefinitionUrl = `${API_BASE_URL}/oid4vp/presentation-definition`;
  const presentationDefinitionOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify(presentationDefinition),
  };
  logger.warn(presentationDefinitionUrl);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Definition to: ${presentationDefinitionUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationDefinitionOptions});
  const presentationDefinitionData = await fetchApiData(
    presentationDefinitionUrl,
    presentationDefinitionOptions
  );
  logger.info("Created presentation?");
  logger.trace(JSON.stringify(presentationDefinitionData));
  logger.trace(presentationDefinitionData.pres_def_id);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created Presentation Definition`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Definition ID: ${presentationDefinitionData.pres_def_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationDefinitionData});


  // Create Presentation Request
  const presentationRequestUrl = `${API_BASE_URL}/oid4vp/request`;
  const presentationRequestOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      "pres_def_id": presentationDefinitionData.pres_def_id,
      "vp_formats": {
        "jwt_vc": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vp": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vc_json": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vp_json": { "alg": [ "ES256", "EdDSA" ] }
      },
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions});
  const presentationRequestData = await fetchApiData(
    presentationRequestUrl,
    presentationRequestOptions
  );
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});

  // Grab the relevant data and store it for later reference while waiting for the webhooks from ACA-Py
  let code = presentationRequestData.request_uri;
  presentationCache.set(presentationDefinitionData.pres_def_id, { presentationDefinitionData, presentationRequestData, presentationId: presentationId });
  logger.trace(JSON.stringify(presentationRequestData, null, 2));

  // Generate a QRCode and return it to the browser (HTMX replaces a div with our current response)
  var qrcode = new QRCode({
    content: code,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  qrcode = qrcode.svg()
  qrcode = qrcode.substring(qrcode.indexOf('?>')+2,qrcode.length)
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(qrcode);

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
}

// Begin SD-JWT Presentation Flow
async function create_sd_jwt_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create Presentation Definition
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating Presentation Definition."});
  const presentationDefinition = {"pres_def": {
    "id": uuidv4(),
    "purpose": "Present basic profile info",
    "input_descriptors": [
      {
        "format": {
          "vc+sd-jwt": {}
        },
        "id": "ID Card",
        "name": "Profile",
        "purpose": "Present basic profile info",
        "constraints": {
          "limit_disclosure": "required",
          "fields": [
            {
              "path": [
                "$.vct"
              ],
              "filter": {
                "type": "string"
              }
            },
            {
              "path": [
                "$.family_name"
              ]
            },
            {
              "path": [
                "$.given_name"
              ]
            },
            {
              "path": [
                "$.something_nested.key1.key2.key3"
              ]
            },
          ]
        }
      }
    ]
  }};

  const presentationDefinitionUrl = `${API_BASE_URL}/oid4vp/presentation-definition`;
  const presentationDefinitionOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify(presentationDefinition),
  };
  logger.warn(presentationDefinitionUrl);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Definition to: ${presentationDefinitionUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationDefinitionOptions});
  const presentationDefinitionData = await fetchApiData(
    presentationDefinitionUrl,
    presentationDefinitionOptions
  );
  logger.info("Created presentation?");
  logger.trace(JSON.stringify(presentationDefinitionData));
  logger.trace(presentationDefinitionData.pres_def_id);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created Presentation Definition`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Definition ID: ${presentationDefinitionData.pres_def_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationDefinitionData});


  // Create Presentation Request
  const presentationRequestUrl = `${API_BASE_URL}/oid4vp/request`;
  const presentationRequestOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      "pres_def_id": presentationDefinitionData.pres_def_id,
      "vp_formats": {
        "vc+sd-jwt": {
            "sd-jwt_alg_values": [
                "ES256",
                "ES384"
            ],
            "kb-jwt_alg_values": [
                "ES256",
                "ES384"
            ]
        }
      },
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions});
  const presentationRequestData = await fetchApiData(
    presentationRequestUrl,
    presentationRequestOptions
  );
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});

  // Grab the relevant data and store it for later reference while waiting for the webhooks from ACA-Py
  let code = presentationRequestData.request_uri;
  presentationCache.set(presentationDefinitionData.pres_def_id, { presentationDefinitionData, presentationRequestData, presentationId: presentationId });
  logger.trace(JSON.stringify(presentationRequestData, null, 2));

  // Generate a QRCode and return it to the browser (HTMX replaces a div with our current response)
  var qrcode = new QRCode({
    content: code,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  qrcode = qrcode.svg()
  qrcode = qrcode.substring(qrcode.indexOf('?>')+2,qrcode.length)
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(qrcode);

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
}

// ##     ## ######## ##     ## ##     ##
// ##     ##    ##    ###   ###  ##   ##
// ##     ##    ##    #### ####   ## ##
// #########    ##    ## ### ##    ###
// ##     ##    ##    ##     ##   ## ##
// ##     ##    ##    ##     ##  ##   ##
// ##     ##    ##    ##     ## ##     ##
// ######## ##     ## ######## ##    ## ########  ######
// ##       ##     ## ##       ###   ##    ##    ##    ##
// ##       ##     ## ##       ####  ##    ##    ##
// ######   ##     ## ######   ## ## ##    ##     ######
// ##        ##   ##  ##       ##  ####    ##          ##
// ##         ## ##   ##       ##   ###    ##    ##    ##
// ########    ###    ######## ##    ##    ##     ######

function handleEvents(event_type, req, res) {
  // Send headers indicating that this is an HTMX stream
  res.writeHead(200, {
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Content-Type": "text/event-stream",
  });

  // Reset data
  logger.trace("HTMX Stream started!");
  res.write(`event: debug\ndata: \n\n`);
  res.write(`event: qrcode\ndata: \n\n`);
  let state = ""

  // When we receive an event
  events.on(`${event_type}-${req.params.id}`, (data) => {

    // Send messages verbatim
    if (data.type == "message") {
      res.write(`event: message\ndata: ${data.message}<br />\n\n`);
      return;
    }
    // Debug messages get special formatting
    if (data.type == "debug-message") {
      res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; ${data.message}: ${JSON.stringify(data.data)}</div>\n\n`);
    }

    // Webhooks mean that ACA-Py sent us data regarding presentations or credential issuance
    if (data.type == "webhook") {

      // Log it for debugging
      logger.trace(JSON.stringify(data, null, 2));
      res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; Webhook data: ${JSON.stringify(data.data)}</div>\n\n`);

      // Grab the state
      state = data?.data?.state;

      // Handle OID4VP webhooks
      if (data.path == "/webhook/topic/oid4vp/") {
        if (state == "request-retrieved")
          res.write(`event: status\ndata: <div style="text-align: center;">QRCode Scanned, awaiting presentation...</div>\n\n`);
        if (state == "presentation-invalid")
          res.write(`event: status\ndata: <div style="text-align: center;">Presentaion verification failed</div>\n\n`);
        if (state == "presentation-valid")
          res.write(`event: status\ndata: <div style="text-align: center;">Presentation Verified!</div>\n\n`);
      }

      // Handle OID4VCI webhooks
      if (data.path == "/webhook/topic/oid4vci/") {
        if (state == "issued") {
          res.write(`event: qrcode\ndata: Credential Issued!\n\n`);
          return;
        }
      }
    }
    res.write(`event: debug\ndata: ${JSON.stringify(data)}\n\n`);

    // For OID4VCI: when we receive a "qrcode" message, generate a code and send it to the browser
    if ("qrcode" in data) {
      var qrcode = new QRCode({
        content: data.qrcode,
        padding: 4,
        width: 256,
        height: 256,
        color: "#000000",
        background: "#ffffff",
        ecl: "M",
      });
      logger.debug(data.qrcode);
      res.write(`event: qrcode\ndata: ${qrcode.svg().replace(/\r?\n|\r/g, " ")}\n\n`);
    }
  });

  res.on("close", () => {
    res.end();
  });
}


// ########   #######  ##     ## ######## ########  ######
// ##     ## ##     ## ##     ##    ##    ##       ##    ##
// ##     ## ##     ## ##     ##    ##    ##       ##
// ########  ##     ## ##     ##    ##    ######    ######
// ##   ##   ##     ## ##     ##    ##    ##             ##
// ##    ##  ##     ## ##     ##    ##    ##       ##    ##
// ##     ##  #######   #######     ##    ########  ######
// Express.js Routes

// Render main app
app.get("/", (req, res) => {
  res.render("index", {"registrationId": uuidv4()});
});

const fetchApiData = async (url, options) => {
  const response = await fetch(url, options);
  return await response.json();
};

const token = await fetchApiData(
  `${API_BASE_URL}/multitenancy/wallet`,
  {
    method: "POST",
    headers: {
      accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(
      {
          "label": "Alice",
          "wallet_type": "askar",
      }
    )
  }
);

console.log("_______TOKEN________\n\n\n");
console.log(token);

// Render Credential Issuance form
app.get("/issue", (req, res) => {
  res.render("issue-form", {"page": "register", "registrationId": uuidv4()});
});
app.get("/issue/select", (req, res) => {
  console.log(req.query);
  res.render(`issue/${req.query["credential-type"]}`, {"page": "register", "registrationId": uuidv4()});
});

app.post("/issue", (req, res, next) => {
  // Begin Credential issuance flow
  //events.on(`${event_type}-${req.params.id}`, (data) => {
    console.log(req.body);
    switch(req.body["credential-type"]) {
      case "jwt":
        issue_jwt_credential(req, res).catch(next);
        break;
      case "sdjwt":
        issue_sdjwt_credential(req, res).catch(next);
        break;
      default:
        res.status(400).send("");
    }
  });

  // Event Stream for Issuance page
  app.get("/stream/issue/:id", (req, res) => {
    handleEvents("issuance", req, res);
  });

  app.get("/present/select/:id", (req, res) => {
    console.log(req.query);
    res.render(`present/${req.query["credential-type"]}`, {"page": "register", "presentationId": req.params.id});
  });

  // Render Presentation Exchange form
  app.get("/present", (req, res) => {
    res.render("presentation", {"page": "present", "presentationId": uuidv4()});
  });

  app.get("/present/create/:id", (req, res, next) => {
    // Begin Presentation Exchange flow

    switch(req.query["credential-type"]) {
      case "jwt":
        create_jwt_vc_presentation(req, res).catch(next);
        break;
      case "sdjwt":
        create_sd_jwt_presentation(req, res).catch(next);
        break;
      default:
        res.status(400).send("");
    }
  });

  // Event Stream for Presentation page
  app.get("/stream/present/:id", (req, res) => {
    handleEvents("presentation", req, res);
  });

  // ##      ## ######## ########  ##     ##  #######   #######  ##    ##  ######
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##   ##  ##    ##
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##  ##   ##
  // ##  ##  ## ######   ########  ######### ##     ## ##     ## #####     ######
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##  ##         ##
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##   ##  ##    ##
  //  ###  ###  ######## ########  ##     ##  #######   #######  ##    ##  ######
  // ACA-Py sends webhook events when something happens within ACA-Py (such as
    // when a credential is issued or a presentation has been varified). These
  // webhooks showcase the current state of ACA-Py flows and can be acted upon to
  // give users up-to-date and realtime info.

    app.post("/webhook/*", (req, res, next) => {
      logger.trace("Webhook received");
      logger.trace(req.path);
      logger.trace(JSON.stringify(req.body));
      if (req.path == "/webhook/topic/oid4vci/") {
        // If there's no exchange ID, we can't look up the request
        if (!req.body.exchange_id) return;

        // Check to see if this belongs to us
        let exchange = exchangeCache.get(req.body.exchange_id);
        if (!exchange) return;

        // Dispatch event
        events.emit(`issuance-${exchange.registrationId}`, {type: "webhook", path: req.path, data: req.body});
      }
      if (req.path == "/webhook/topic/oid4vp/") {
        // If there's no presentation definition ID, we can't look up the request
        if (!req.body.pres_def_id) return;

        // Check to see if this belongs to us
        let exchange = presentationCache.get(req.body.pres_def_id);
        if (!exchange) return;

        // Dispatch event
        events.emit(`presentation-${exchange.presentationId}`, {type: "webhook", path: req.path, data: req.body});
      }
    });

  app.listen(3000, () => {
    console.log("App listening on port 3000");
  });
