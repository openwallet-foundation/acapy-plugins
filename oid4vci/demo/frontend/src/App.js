import React from 'react';
import './App.css';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import InputForm from './InputForm';
import RegistrationPage from './AdminPage'
import QRCodePage from './QRCodePage';
import "bootstrap/dist/css/bootstrap.min.css"

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/" exact element={<RegistrationPage/>} />
          <Route path="/input" exact element={<InputForm/>} />
          <Route path="/qr-code" element={<QRCodePage/>} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
