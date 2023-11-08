import React, { useState } from "react";
import axios from "axios";
import { useNavigate, useLocation } from "react-router-dom";
import img1 from "./img/img1.png";
import img2 from "./img/img2.png";
import img3 from "./img/img3.png";

const FormPage = () => {
  const navigate = useNavigate();
  const [selectedCredential, setSelectedCredential] = useState("");
  const { state } = useLocation();
  const { firstName, lastName, email } = state;

  const handleCredentialSelect = (credential) => {
    setSelectedCredential(credential);
  };

  const handleSubmit = () => {
    // Set the Axios configuration for CORS and credentials
    axios.defaults.withCredentials = true; // Enable credentials (cookies, etc.)
    axios.defaults.headers.common['Access-Control-Allow-Origin'] = 'http://localhost:3001'; // Adjust the origin as needed

    // api call to controller, `POST /exchange/submit`
    axios
      .post("http://localhost:3001/oid4vci/exchange/create", {
        credential_subject: {
          name: firstName,
          lastname: lastName,
          email,
        },
        supported_cred_id: selectedCredential,
      })
      .then((response) => {
        console.log(response.data);
        const {exchange_id} = response.data
          // TODO: call offer endpoint

          const queryParams = {
            credentials: [selectedCredential],
            user_pin_required: false,
            exchange_id: exchange_id,
          };
          axios.get("http://localhost:3001/oid4vci/draft-11/credential-offer", { params: queryParams })
          .then((response) => {
            console.log(response.data);
            const credentialOffer = response.data;
            const {exchange_id} = response.data;
            navigate(`/qr-code`, { state: { credentialOffer, exchange_id: exchange_id } });
          })
        })
      .catch((error) => {
        console.error(error);
      });
  };

  return (
    <div>
      <h2>Select the Credential You Would Like to Collect</h2>
      <button onClick={() => navigate("/")}>Back</button>
      <div className="credential-options">
        <img
          src={img1}
          width={250}
          height={150}
          alt="UniversityDegreeCredential"
          onClick={() => handleCredentialSelect("UniversityDegreeCredential")}
        />
        <img
          src={img2}
          width={250}
          height={150}
          alt="UniversityDegreeCredential"
          onClick={() => handleCredentialSelect("UniversityDegreeCredential")}
        />
        <img
          src={img3}
          width={250}
          height={150}
          alt="UniversityDegreeCredential"
          onClick={() => handleCredentialSelect("UniversityDegreeCredential")}
        />
      </div>
      <button onClick={handleSubmit}>Submit</button>
    </div>
  );
};

export default FormPage;
