import React, { useEffect, useState } from "react";
import axios from "axios";
import { useLocation, useNavigate } from "react-router-dom";
import QRCode from "qrcode.react";
import { useInterval } from './useInterval';

const QRCodePage = () => {
  const navigate = useNavigate();
  const { state } = useLocation();
  console.log(state)
  const { credentialOffer, exchange_id } = state;
  const [qrData, setQRData] = useState("");
  const jsonStr = JSON.stringify(credentialOffer);
  const encodedJson = encodeURIComponent(jsonStr);
  const urlOffer = `openid-credential-offer://?credential_offer=${encodedJson}`
  // Define a callback function that will be executed at each interval
  const pollState = () => {
    // Set the Axios configuration for CORS and credentials
    axios.defaults.withCredentials = true; // Enable credentials (cookies, etc.)
    axios.defaults.headers.common['Access-Control-Allow-Origin'] = 'http://localhost:3001'; // Adjust the origin as needed

    axios
      .get(`http://localhost:3001/oid4vci/exchange/records`, {exchange_id: exchange_id})
      .then((response) => {
        console.log(response.data);
        if(response.data.state === "completed"){
            navigate(`/`);
        }
      })
      .catch((error) => {
        console.error(error);
      });
  };

  // Use the useInterval hook to start polling every 1000ms (1 second)
  useInterval(pollState, 1000);
  useEffect(() => {
    // Combine the data from the URL params to generate the QR code data.
    setQRData(urlOffer);
  }, [urlOffer]);

  return (
    <div>
      <h2>QR Code Page</h2>
      <QRCode value={qrData} />
    </div>
  );
};

export default QRCodePage;
