import React, { useState } from "react";
import axios from "axios";
import { useNavigate, useLocation } from "react-router-dom";
import "./InputForm.css"

const InputForm = () => {
  const navigate = useNavigate();
  const { state } = useLocation();
  const { supportedCredId, did } = state;
  console.log(supportedCredId);
  console.log(did);
  const [firstName, setFirstName] = useState("Sally");
  const [lastName, setLastName] = useState("Sparrow");
  const [email, setEmail] = useState("SallySparrow@email.com");
  const API_BASE_URL = "http://localhost:3001";

  const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
  const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
  const headers = {
    accept: "application/json",
  };

  const handleFirstNameChange = (e) => {
    setFirstName(e.target.value);
  };

  const handleLastNameChange = (e) => {
    setLastName(e.target.value);
  };

  const handleEmailChange = (e) => {
    setEmail(e.target.value);
  };

  const getOffer = async () => {
    try {
      axios.defaults.withCredentials = true;
      axios.defaults.headers.common["Access-Control-Allow-Origin"] =
        API_BASE_URL;

      const exchangeResponse = await axios.post(exchangeCreateUrl, {
        credential_subject: { name: firstName, lastname: lastName, email },
        did,
        supported_cred_id: supportedCredId,
      });

      const exchangeId = exchangeResponse.data.exchange_id;

      const queryParams = {
        user_pin_required: false,
        exchange_id: exchangeId,
      };

      const offerResponse = await axios.get(credentialOfferUrl, {
        params: queryParams,
        headers: headers,
      });

      const credentialOffer = offerResponse.data;

      navigate(`/qr-code`, { state: { credentialOffer, exchangeId } });
    } catch (error) {
      console.error("Error during API call:", error);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    getOffer();
  };

  return (
    <div class="container" style={{padding: "3px"}}>
      <div class="row">
      <div class="col-md-3"></div>
      <div class="col-md-6 input-wrapper">
      <h1 class="input-h1">Input Form</h1>

      <hr />

      <div>
      <form class="input-form" onSubmit={handleSubmit}>
        <div class="input-form-group">
          <label htmlFor="firstName" class="input-label">First Name</label>
          <input
            type="text"
            id="firstName"
            value={firstName}
            onChange={handleFirstNameChange}
	    class="input-form-control"
          />
        </div>
        <div class="input-form-group">
          <label htmlFor="lastName" class="input-label">Last Name</label>
          <input
            type="text"
            id="lastName"
            value={lastName}
            onChange={handleLastNameChange}
	    class="input-form-control"
          />
        </div>
        <div class="input-form-group">
          <label htmlFor="email" class="input-label">Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={handleEmailChange}
	    class="input-form-control"
          />
        </div>
	<div class="input-form-group">
        <button type="submit" class="btn btn-warning btn-lg input-form-button">Share</button>
	</div>
      </form>
      </div>
      </div>
      </div>
    </div>
  );
};

export default InputForm;
