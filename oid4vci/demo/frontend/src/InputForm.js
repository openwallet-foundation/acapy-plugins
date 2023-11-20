import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';


const InputForm = () => {
  const navigate = useNavigate();
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [did, setDid] = useState('');

  const handleFirstNameChange = (e) => {
    setFirstName(e.target.value);
  };

  const handleLastNameChange = (e) => {
    setLastName(e.target.value);
  };

  const handleEmailChange = (e) => {
    setEmail(e.target.value);
  };

  const handleDidChange = (e) => {
    setDid(e.target.value);
  };

  const handleShareClick = () => {
    navigate(`/credentials`,{ state: {firstName:firstName, lastName:lastName, email:email, did:did}});
    
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
          <div>
            <label htmlFor="did">Did:</label>
            <input
              type="did"
              id="did"
              value={did}
              onChange={handleDidChange}
            />
          </div>
        <button type="button" onClick={handleShareClick}>
          Share
        </button>
      </form>
    </div>
  );
};

export default InputForm;
