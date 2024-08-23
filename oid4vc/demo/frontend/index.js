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

const my_stream = {
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
}, my_stream);
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
app.use(express.static("public"));

const events = new EventEmitter();
const exchangeCache = new NodeCache({ stdTTL: 300, checkperiod: 400 });

const API_BASE_URL = process.env.API_BASE_URL || "http://localhost:3001";
const API_KEY = process.env.API_KEY;

app.get("/", (req, res) => {
	res.render("index", {"registrationId": uuidv4()});
});

app.get("/issue", (req, res) => {
	res.render("register-form", {"page": "register", "registrationId": uuidv4()});
});


app.get("/present", (req, res) => {
	res.render("presentation", {"page": "present", "registrationId": uuidv4()});
});

app.post("/present/create", (req, res, next) => {
	create_presentation(req, res).catch(next);
});
async function create_presentation(req, res) {
	//res.status(404).send("");
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
								"$.vc.credentialSubject.name",
								"$.credentialSubject.name"
							],
							"filter": {
								"type": "string",
								"pattern": "^.{1,64}$"
							}
						},
						{
							"name": "lastname",
							"path": [
								"$.vc.credentialSubject.lastname",
								"$.credentialSubject.lastname"
							],
							"filter": {
								"type": "string",
								"pattern": "^.{1,64}$"
							}
						},
						{
							"name": "email",
							"path": [
								"$.vc.credentialSubject.email",
								"$.credentialSubject.email"
							],
							"filter": {
								"type": "string",
								"pattern": "^.{1,128}$"
							}
						}
					]
				}
			}
		]
	}
	};

	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Received credential data."});

	const presentationDefinitionUrl = () =>
		`${API_BASE_URL}/oid4vp/presentation-definition`;
	const presentationRequestUrl = () => `${API_BASE_URL}/oid4vp/request`;

	const commonHeaders = {
		accept: "application/json",
		"X-API-KEY": API_KEY,
		"Content-Type": "application/json",
	};

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
	const presentationDefinitionData = await fetchApiData(
		presentationDefinitionUrl(),
		presentationDefinitionOptions()
	);
	//const supportedCredId = supportedCredentialData.supported_cred_id;
	logger.info("Created presentation?");
	logger.trace(JSON.stringify(presentationDefinitionData));
	logger.trace(presentationDefinitionData.pres_def_id);
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
	const presentationRequestData = await fetchApiData(
		presentationRequestUrl(),
		presentationRequestOptions()
	);
	let code = presentationRequestData.request_uri;
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
		if (data.type == "webhook") {
			if (data.data.state == state)
				return;

			state = data.data.state;
			if (state != "offer") {
				res.write(`event: qrcode\ndata: Credential Issued!\n\n`);
				res.close();
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
	//events.emit(`r${req.body.registrationId}`, req.body);
	//return;
	//res.send(`Success!<br /><pre><code>${JSON.stringify(req.body)}</code></pre>`);
	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Received credential data."});

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




	const supportedCredentialData = await fetchApiData(
		createCredentialSupportedUrl(),
		createCredentialSupportedOptions()
	);

	const supportedCredId = supportedCredentialData.supported_cred_id;

	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Creating DID."});
	const didData = await fetchApiData(createDidUrl, createDidOptions());

	const { did } = didData;
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Created DID: ${did}`});

	logger.info(did);
	logger.info(supportedCredId);
	//navigate(`/input`, { state: { did, supportedCredId } });
	//console.error("Error during registration:", error);


	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
	const exchangeResponse = await axios.post(exchangeCreateUrl, {
		credential_subject: { name: firstName, lastname: lastName, email },
		verification_method: did+"#0",
		supported_cred_id: supportedCredId,
	});

	const exchangeId = exchangeResponse.data.exchange_id;
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});

	const queryParams = {
		user_pin_required: false,
		exchange_id: exchangeId,
	};

	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
	const offerResponse = await axios.get(credentialOfferUrl, {
		params: queryParams,
		headers: headers,
	});

	const credentialOffer = offerResponse.data;

	logger.info(JSON.stringify(offerResponse.data));
	logger.info(exchangeId);
	const encodedJSON = encodeURIComponent(JSON.stringify(credentialOffer));
	const qrcode = `openid-credential-offer://?credential_offer=${encodedJSON}`;
	events.emit(`r${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
	events.emit(`r${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
	exchangeCache.set(exchangeId, { exchangeId, credentialOffer, did, supportedCredId, registrationId: req.body.registrationId });
	//navigate(`/qr-code`, { state: { credentialOffer, exchangeId } });
	//console.error("Error during API call:", error);
	//await getOffer();
	//return;

	const pollState = async () => {
		try {
			const response = await axios.get(
				`${API_BASE_URL}/oid4vci/exchange/records?exchange_id=${exchangeId}`,
				{
					params: { exchange_id: exchangeId },
					headers: headers,
				}
			);

			console.log(response.data);

			events.emit(`r${req.body.registrationId}`, {type: "webhook", data: response.data.results[0]});
			if (response.data.results[0].state === "issued") {
				//navigate(`/`);
				events.emit(`r${req.body.registrationId}`, {type: "message", message: "Credential issued, closing connection."});
				return;
			}
		} catch (error) {
			console.error("Error during API call:", error);
		}
		setTimeout(pollState, 1000);
	};
	// Use the useInterval hook to start polling every 1000ms (1 second)
	events.emit(`r${req.body.registrationId}`, {type: "message", message: "Begin polling until credential has been issued."});
	await pollState();
	setTimeout(pollState, 1000);

	return;
	//const { credentialOffer, exchangeId } = state;
	const [qrData, setQRData] = useState("");
	const jsonStr = JSON.stringify(credentialOffer);
	const encodedJson = encodeURIComponent(jsonStr);
	const urlOffer = `openid-credential-offer://?credential_offer=${encodedJson}`;


	res.send(`Success!<br /><pre><code>${JSON.stringify(req.body)}</code></pre>`);
}

//*
app.listen(3000, () => {
	console.log("App listening on port 3000");
});

// */
