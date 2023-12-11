import React, { useEffect, useState } from "react";
import axios from "axios";
import { useLocation, useNavigate } from "react-router-dom";
import QRCode from "qrcode.react";
import { useInterval } from "./useInterval";
import "./InputForm.css"

const QRCodePage = () => {
  const navigate = useNavigate();
  const { state } = useLocation();
  console.log(state);
  const { credentialOffer, exchangeId } = state;
  const [qrData, setQRData] = useState("");
  const jsonStr = JSON.stringify(credentialOffer);
  const encodedJson = encodeURIComponent(jsonStr);
  const urlOffer = `openid-credential-offer://?credential_offer=${encodedJson}`;
  const API_BASE_URL = "http://localhost:3001";

  const headers = {
    withCredentials: true,
    "Access-Control-Allow-Origin": API_BASE_URL,
  };

  const pollState = async () => {
    try {
      const response = await axios.get(
        `${API_BASE_URL}/oid4vci/exchange/records`,
        {
          params: { exchange_id: exchangeId },
          headers: headers,
        }
      );

      console.log(response.data);

      if (response.data.results[0].state === "issued") {
        navigate(`/`);
      }
    } catch (error) {
      console.error("Error during API call:", error);
    }
  };

  // Use the useInterval hook to start polling every 1000ms (1 second)
  useInterval(pollState, 1000);
  useEffect(() => {
    // Combine the data from the URL params to generate the QR code data.
    setQRData(urlOffer);
  }, [urlOffer]);

  return (
  <div class="container" style={{ padding: "3px" }}>
    <div class="row">
      <div class="col-md-3"></div>
      <div class="col-md-6 input-wrapper">
        <h1 class="input-h1">QR Code Page</h1>
        <hr />
	<div class="container" style={{ padding: "3px"}}>
	<div class="row">
	<div class="col-md"></div>
        <div class="col-md input-form" style={{ backgroundColor: "white", padding: "3px 5px" }}>
          <QRCode value={qrData} />
        </div>
	<div class="col-md"></div>
	</div>
	</div>
      </div>
      <div class="col-md-3"></div>
    </div>
  </div>
);
};

export default QRCodePage;
