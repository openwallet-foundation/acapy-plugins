import React, { useState } from "react";
import axios from "axios";
import { useNavigate, useLocation } from "react-router-dom";

const InputForm = () => {
  const navigate = useNavigate();
  const { state } = useLocation();
  const { supportedCredId, did } = state;
  console.log(supportedCredId);
  console.log(did);
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
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
    <div>
      <h2>Input Form</h2>

      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="firstName">First Name:</label>
          <input
            type="text"
            id="firstName"
            value={firstName}
            onChange={handleFirstNameChange}
          />
        </div>
        <div>
          <label htmlFor="lastName">Last Name:</label>
          <input
            type="text"
            id="lastName"
            value={lastName}
            onChange={handleLastNameChange}
          />
        </div>
        <div>
          <label htmlFor="email">Email:</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={handleEmailChange}
          />
        </div>
        <button type="submit">Share</button>
      </form>
    </div>
  );
};

export default InputForm;
