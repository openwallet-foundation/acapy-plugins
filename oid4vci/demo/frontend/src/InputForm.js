import React, { useState } from 'react';
import axios from "axios";
import { useNavigate, useLocation } from "react-router-dom";


const InputForm = () => {
  const navigate = useNavigate();
  const { state } = useLocation();
  const { supportedCredId, did } = state;
  console.log(supportedCredId)
  console.log(did)
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');

  const handleFirstNameChange = (e) => {
    setFirstName(e.target.value);
  };

  const handleLastNameChange = (e) => {
    setLastName(e.target.value);
  };

  const handleEmailChange = (e) => {
    setEmail(e.target.value);
  };

  const getOffer = () => {
    // Set the Axios configuration for CORS and credentials
    axios.defaults.withCredentials = true; // Enable credentials (cookies, etc.)
    axios.defaults.headers.common["Access-Control-Allow-Origin"] =
      "http://localhost:3001"; // Adjust the origin as needed
    console.log(firstName, lastName, email, did);

    // api call to controller, `POST /exchange/submit`
    axios
      .post("http://localhost:3001/oid4vci/exchange/create", {
        credential_subject: {
          name: firstName,
          lastname: lastName,
          email,
        },
        did: did,
        supported_cred_id: supportedCredId,
      })
      .then((response) => {
        console.log(response.data);
        const { exchange_id } = response.data;
        // TODO: call offer endpoint

        const queryParams = {
          user_pin_required: false,
          exchange_id: exchange_id,
        };
        console.log("get offer params:");
        console.log(queryParams);
        axios
          .get("http://localhost:3001/oid4vci/credential-offer", {
            params: queryParams,
            headers: {
              accept: "application/json",
            },
          })
          .then((response) => {
            console.log(response.data);
            const credentialOffer = response.data;
            navigate(`/qr-code`, {
              state: { credentialOffer, exchange_id: exchange_id },
            });
          });
      })
      .catch((error) => {
        console.error(error);
      });
  };

  return (
    <div>
      <h2>Input Form</h2>
      
      <form>
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
        <button type="button" onClick={getOffer}>
          Share
        </button>
      </form>
    </div>
  );
};

export default InputForm;
