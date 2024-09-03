import express from "express";

import axios from "axios";

import { v4 as uuidv4 } from "uuid";
import {default as NodeCache } from "node-cache";
import QRCode from "qrcode-svg";

import path from "node:path";

import pino from "pino";
import pino_pretty from "pino-pretty";
import colada from "pino-colada";

import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { EventEmitter } from 'node:events';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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
logger.silent("Logger initialized.");
logger.fatal("Logger initialized.");
logger.error("Logger initialized.");
logger.warn("Logger initialized.");
logger.info("Logger initialized.");
logger.debug("Logger initialized.");
logger.trace("Logger initialized.");

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

app.get("/", (req, res) => {
	res.render("index", {"registrationId": uuidv4()});
});

app.get("/issue", (req, res) => {
	res.render("register-form", {"page": "register", "registrationId": uuidv4()});
});


app.get("/present", (req, res) => {
	res.render("presentation", {"page": "present", "presentationId": uuidv4()});
});

app.post("/present/create/:id", (req, res, next) => {
	create_presentation(req.params.id, req, res).catch(next);
});
async function create_presentation(presentationId, req, res) {
	events.emit(`p${presentationId}`, {type: "message", message: "Creating Presentation Definition."});
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


	const presentationDefinitionUrl = () =>
		`${API_BASE_URL}/oid4vp/presentation-definition`;
	const presentationRequestUrl = () => `${API_BASE_URL}/oid4vp/request`;

	const commonHeaders = {
		accept: "application/json",
		"Content-Type": "application/json",
	};
	if (API_KEY) {
		commonHeaders["X-API-KEY"] =  API_KEY;
	}

	axios.defaults.withCredentials = true;
	axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
	axios.defaults.headers.common["X-API-KEY"] = API_KEY;


	const fetchApiData = async (url, options) => {
		const response = await fetch(url, options);
		return await response.json();
	};
	const presentationDefinitionOptions = () => ({
		method: "POST",
		headers: commonHeaders,
		body: JSON.stringify(presentationDefinition),
	});
	logger.warn(presentationDefinitionUrl());
	events.emit(`p${presentationId}`, {type: "message", message: `Posting Presentation Definition to: ${presentationDefinitionUrl()}`});
	events.emit(`p${presentationId}`, {type: "debug-message", message: "Request options", data: presentationDefinitionOptions()});
	const presentationDefinitionData = await fetchApiData(
		presentationDefinitionUrl(),
		presentationDefinitionOptions()
	);
	logger.info("Created presentation?");
	logger.trace(JSON.stringify(presentationDefinitionData));
	logger.trace(presentationDefinitionData.pres_def_id);
	events.emit(`p${presentationId}`, {type: "message", message: `Created Presentation Definition`});
	events.emit(`p${presentationId}`, {type: "message", message: `Presentation Definition ID: ${presentationDefinitionData.pres_def_id}`});
	events.emit(`p${presentationId}`, {type: "debug-message", message: "Response data", data: presentationDefinitionData});
	const presentationRequestOptions = () => ({
		method: "POST",
		headers: commonHeaders,
		body: JSON.stringify({
			"pres_def_id": presentationDefinitionData.pres_def_id,
			"vp_formats": {
				"jwt_vc_json": { "alg": [ "ES256", "EdDSA" ] },
				"jwt_vp_json": { "alg": [ "ES256", "EdDSA" ] },
				"jwt_vc": { "alg": [ "ES256", "EdDSA" ] },
				"jwt_vp": { "alg": [ "ES256", "EdDSA" ] }
			},
		}),
	});
	events.emit(`p${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
	events.emit(`p${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl()}`});
	events.emit(`p${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions()});
	const presentationRequestData = await fetchApiData(
		presentationRequestUrl(),
		presentationRequestOptions()
	);
	events.emit(`p${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
	events.emit(`p${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
	events.emit(`p${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});
	let code = presentationRequestData.request_uri;
	presentationCache.set(presentationDefinitionData.pres_def_id, { presentationDefinitionData, presentationRequestData, presentationId: presentationId });
	logger.trace(JSON.stringify(presentationRequestData, null, 2));
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
}

app.get("/stream/present/:id", (req, res) => {
	res.writeHead(200, {
		"Connection": "keep-alive",
		"Cache-Control": "no-cache",
		"Content-Type": "text/event-stream",
	});

	logger.trace("Present Stream started!");
	res.write(`event: debug\ndata: \n\n`);
	let state = ""
	events.on(`p${req.params.id}`, (data) => {
		if (data.type == "message") {
			res.write(`event: message\ndata: ${data.message}<br />\n\n`);
			return;
		}
		if (data.type == "debug-message") {
			res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; ${data.message}: ${JSON.stringify(data.data)}</div>\n\n`);
		}
		if (data.type == "webhook") {
			logger.trace(JSON.stringify(data, null, 2));
			res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; Webhook data: ${JSON.stringify(data.data)}</div>\n\n`);
			if (data.data.state == "request-retrieved")
				res.write(`event: status\ndata: <div style="text-align: center;">QRCode Scanned, awaiting presentation...</div>\n\n`);
			if (data.data.state == "presentation-invalid")
				res.write(`event: status\ndata: <div style="text-align: center;">PRESENTATION INVALID</div>\n\n`);
			if (data.data.state == "presentation-valid")
				res.write(`event: status\ndata: <div style="text-align: center;">Presentation Valid</div>\n\n`);
		}
		res.write(`event: debug\ndata: ${JSON.stringify(data)}\n\n`);
	});

	res.on("close", () => {
		res.end();
	});
});


app.get("/stream/issue/:id", (req, res) => {
	res.writeHead(200, {
		"Connection": "keep-alive",
		"Cache-Control": "no-cache",
		"Content-Type": "text/event-stream",
	});

	logger.trace("Counter started!");
	res.write(`event: debug\ndata: \n\n`);
	res.write(`event: qrcode\ndata: \n\n`);
	let state = ""
	events.on(`r${req.params.id}`, (data) => {
		if (data.type == "message") {
			res.write(`event: message\ndata: ${data.message}<br />\n\n`);
			return;
		}
		if (data.type == "debug-message") {
			res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; ${data.message}: ${JSON.stringify(data.data)}</div>\n\n`);
		}
		if (data.type == "webhook") {
			res.write(`event: message\ndata: <div style="overflow-x: scroll; white-space: nowrap;">&gt; Webhook data: ${JSON.stringify(data.data)}</div>\n\n`);
			if (data.data.state == state)
				return;

			state = data.data.state;
			if (state == "issued") {
				res.write(`event: qrcode\ndata: Credential Issued!\n\n`);
				//res.end();
				return;
			}
		}
		res.write(`event: debug\ndata: ${JSON.stringify(data)}\n\n`);
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
});

app.post("/issue", (req, res, next) => {
	issue_credential(req, res).catch(next);
});
async function issue_credential(req, res) {
	res.status(200).send("");
	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Received credential data from user."});

	const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
	const createCredentialSupportedUrl = () =>
		`${API_BASE_URL}/oid4vci/credential-supported/create`;
	const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
	const createDidUrl = `${API_BASE_URL}/did/jwk/create`;

	const headers = {
		accept: "application/json",
	};
	const commonHeaders = {
		accept: "application/json",
		"Content-Type": "application/json",
	};
	if (API_KEY) {
		commonHeaders["X-API-KEY"] =  API_KEY;
	}


	const { fname: firstName, lname: lastName, email } = req.body
	logger.info(firstName);

	axios.defaults.withCredentials = true;
	axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
	axios.defaults.headers.common["X-API-KEY"] = API_KEY;


	const fetchApiData = async (url, options) => {
		const response = await fetch(url, options);
		return await response.json();
	};


	const createCredentialSupportedOptions = () => ({
		method: "POST",
		headers: commonHeaders,
		body: JSON.stringify({
			cryptographic_binding_methods_supported: ["did"],
			cryptographic_suites_supported: ["EdDSA"],
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
			format_data: {
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
				types: ["VerifiableCredential", "UniversityDegreeCredential"],
			},
			id: "UniversityDegreeCredential",
			vc_additional_data: {
				"@context": [
					"https://www.w3.org/2018/credentials/v1",
					"https://www.w3.org/2018/credentials/examples/v1",
				],
				type: ["VerifiableCredential", "UniversityDegreeCredential"],
			},
		}),
	});


	const createDidOptions = () => ({
		method: "POST",
		headers: commonHeaders,
		body: JSON.stringify({
			key_type: "p256",
		}),
	});




	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl()}`});
	events.emit(`r${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions()});
	const supportedCredentialData = await fetchApiData(
		createCredentialSupportedUrl(),
		createCredentialSupportedOptions()
	);

	const supportedCredId = supportedCredentialData.supported_cred_id;

	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Creating DID."});
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Posting Create DID Request to: ${createDidUrl}`});
	events.emit(`r${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createDidOptions()});
	const didData = await fetchApiData(createDidUrl, createDidOptions());

	const { did } = didData;
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Created DID: ${did}`});

	logger.info(did);
	logger.info(supportedCredId);


	const exchangeCreateOptions = {
		credential_subject: { id: req.body.registrationId, first_name: firstName, last_name: lastName, email },
		verification_method: did+"#0",
		supported_cred_id: supportedCredId,
	};
	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
	events.emit(`r${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
	const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions);

	const exchangeId = exchangeResponse.data.exchange_id;
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});

	const queryParams = {
		user_pin_required: false,
		exchange_id: exchangeId,
	};

	const credentialOfferOptions = {
		params: queryParams,
		headers: headers,
	};
	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
	events.emit(`r${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
	const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);

	const credentialOffer = offerResponse.data;

	logger.info(JSON.stringify(offerResponse.data));
	logger.info(exchangeId);
	const encodedJSON = encodeURIComponent(JSON.stringify(credentialOffer));
	const qrcode = `openid-credential-offer://?credential_offer=${encodedJSON}`;
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
	events.emit(`r${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
	exchangeCache.set(exchangeId, { exchangeId, credentialOffer, did, supportedCredId, registrationId: req.body.registrationId });

	// Use the useInterval hook to start polling every 1000ms (1 second)
	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
}

app.post("/webhook/*", (req, res, next) => {
	logger.trace("Webhook received");
	logger.trace(req.path);
	logger.trace(JSON.stringify(req.body));
	if (req.path == "/webhook/topic/oid4vci/") {
		if (!req.body.exchange_id) return;
		let exchange = exchangeCache.get(req.body.exchange_id);
		if (!exchange) return;

		events.emit(`r${exchange.registrationId}`, {type: "webhook", data: req.body});
	}
	if (req.path == "/webhook/topic/oid4vp/") {
		if (!req.body.pres_def_id) return;
		let exchange = presentationCache.get(req.body.pres_def_id);
		if (!exchange) return;

		events.emit(`p${exchange.presentationId}`, {type: "webhook", data: req.body});
	}
});

//*
app.listen(3000, () => {
	console.log("App listening on port 3000");
});

// */