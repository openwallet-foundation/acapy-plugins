import React from 'react';
import './App.css';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import FormPage from './FormPage';
import InputForm from './InputForm';
import QRCodePage from './QRCodePage';

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/" exact element={<InputForm/>} />
          <Route path="/credentials" element={<FormPage/>} />
          <Route path="/qr-code" element={<QRCodePage/>} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
