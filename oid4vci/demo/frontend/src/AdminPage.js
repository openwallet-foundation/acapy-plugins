import React from "react";
import { useNavigate } from "react-router-dom";

const RegistrationPage = () => {
  const navigate = useNavigate();

  const API_BASE_URL = "http://localhost:3001";
  const API_KEY = "thisistheplace";
  const createCredentialSupportedUrl = () =>
    `${API_BASE_URL}/oid4vci/credential-supported/create`;
  const createDidUrl = () => `${API_BASE_URL}/wallet/did/create`;

  const commonHeaders = {
    accept: "application/json",
    "X-API-KEY": API_KEY,
    "Content-Type": "application/json",
  };

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };
  const createCredentialSupportedOptions = () => ({
    method: "POST",
    headers: commonHeaders,
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

  const createDidOptions = () => ({
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      method: "key",
    }),
  });

  const handleRegistration = async () => {
    try {
      const supportedCredentialData = await fetchApiData(
        createCredentialSupportedUrl(),
        createCredentialSupportedOptions()
      );

      const supportedCredId = supportedCredentialData.supported_cred_id;

      const didData = await fetchApiData(createDidUrl(), createDidOptions());

      const { did } = didData.result;

      navigate(`/input`, { state: { did, supportedCredId } });
    } catch (error) {
      console.error("Error during registration:", error);
    }
  };

  return (
    <div>
      <h1>Registration Page</h1>
      {/* registration form */}
      <button onClick={handleRegistration}>Register</button>
    </div>
  );
};

export default RegistrationPage;
