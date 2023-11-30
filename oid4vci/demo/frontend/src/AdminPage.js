import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

const RegistrationPage = () => {
  const navigate = useNavigate();
  const getFirstApiUrl = () =>
    "http://localhost:3001/oid4vci/credential-supported/create";

  const getFirstRequestOptions = () => ({
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
  });

  const getSecondApiUrl = () => "http://localhost:3001/wallet/did/create";

  const getSecondRequestOptions = () => ({
    method: "POST",
    headers: {
      accept: "application/json",
      "X-API-KEY": "thisistheplace",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      method: "key",
    }),
  });

  const handleRegistration = async () => {
    try {
      const firstApiUrl = getFirstApiUrl();
      const firstRequestOptions = getFirstRequestOptions();

      const firstApiResponse = await fetch(firstApiUrl, firstRequestOptions);
      const firstApiData = await firstApiResponse.json();

      const supportedCredId = firstApiData.supported_cred_id;

      const secondApiUrl = getSecondApiUrl();
      const secondRequestOptions = getSecondRequestOptions();

      const secondApiResponse = await fetch(secondApiUrl, secondRequestOptions);
      const secondApiData = await secondApiResponse.json();

      const { did } = secondApiData.result;

      navigate(`/input`, { state: { did, supportedCredId } });
    } catch (error) {
      console.error("Error during registration:", error);
    }
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
