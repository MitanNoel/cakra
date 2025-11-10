import React, { createContext, useContext, useState, useEffect } from 'react';

const ApiContext = createContext();

export const useApi = () => useContext(ApiContext);

export const ApiProvider = ({ children }) => {
  const [apiStatus, setApiStatus] = useState('Connecting...');
  const [apiVersion, setApiVersion] = useState('N/A');
  const apiEndpoint = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const checkApiStatus = async () => {
      try {
        const response = await fetch(`${apiEndpoint}/api/v1/health`);
        if (response.ok) {
          const data = await response.json();
          setApiStatus('Connected');
          setApiVersion(data.version || 'v1.0.0');
        } else {
          setApiStatus('Error');
          setApiVersion('N/A');
        }
      } catch (error) {
        setApiStatus('Disconnected');
        setApiVersion('N/A');
      }
    };

    checkApiStatus();
    // Check every 30 seconds
    const interval = setInterval(checkApiStatus, 30000);
    return () => clearInterval(interval);
  }, [apiEndpoint]);

  return (
    <ApiContext.Provider value={{ apiStatus, apiVersion, apiEndpoint }}>
      {children}
    </ApiContext.Provider>
  );
};