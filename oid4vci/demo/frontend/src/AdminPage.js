import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

const RegistrationPage = () => {
  const navigate = useNavigate();

  const handleRegistration = () => {
    // First API call
    const firstApiUrl =
      "http://localhost:3001/oid4vci/credential-supported/create";

    const firstRequestOptions = {
      method: "POST",
      headers: {
        accept: "application/json",
        "X-API-KEY": "thisistheplace",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        cryptographic_binding_methods_supported: ["did"],
        cryptographic_suites_supported: ["ES256K"],
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
    };

    fetch(firstApiUrl, firstRequestOptions)
      .then((response) => response.json())
      .then((data) => {

        // Assuming the response contains a supported_cred_id
        const supportedCredId = data.supported_cred_id;

        const secondApiUrl = "http://localhost:3001/wallet/did/create";

        const secondRequestOptions = {
          method: "POST",
          headers: {
            accept: "application/json",
            "X-API-KEY": "thisistheplace",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            method: "key",
          }),
        };

        fetch(secondApiUrl, secondRequestOptions)
          .then((response) => response.json())
          .then((data) => {

            // Extracting the 'did' from the response
            const {did} = data.result;
            
            // Redirect with the IDs, did, and supported_cred_id
            navigate(
              `/input`, { state : {did, supportedCredId }}
            );
          })
          .catch((error) => {
            console.error("Error fetching second API:", error);
          });
      })
      .catch((error) => {
        console.error("Error fetching first API:", error);
      });
  };

  return (
    <div>
      <h1>Registration Page</h1>
      {/* Your registration form */}
      <button onClick={handleRegistration}>Register</button>
    </div>
  );
};

export default RegistrationPage;
