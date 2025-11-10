import React, { createContext, useContext, useState, useEffect } from 'react';

const ApiContext = createContext();

export const useApi = () => useContext(ApiContext);

export const ApiProvider = ({ children }) => {
  const [apiStatus, setApiStatus] = useState('Connecting...');
  const [apiVersion, setApiVersion] = useState('N/A');
  const apiEndpoint = 'https://api.cakra.local';

  const mockFetch = (endpoint) => {
    return new Promise(resolve => {
      setTimeout(() => {
        if (endpoint === '/health') {
          resolve({ ok: true, json: () => Promise.resolve({ status: 'Connected' }) });
        } else if (endpoint === '/version') {
          resolve({ ok: true, json: () => Promise.resolve({ version: 'v1.2.0' }) });
        }
      }, 500);
    });
  };

  useEffect(() => {
    const checkApiStatus = async () => {
      try {
        const healthResponse = await mockFetch('/health');
        if (healthResponse.ok) {
          const healthData = await healthResponse.json();
          setApiStatus(healthData.status);
        } else {
          setApiStatus('Disconnected');
        }

        const versionResponse = await mockFetch('/version');
        if (versionResponse.ok) {
          const versionData = await versionResponse.json();
          setApiVersion(versionData.version);
        }
      } catch (error) {
        setApiStatus('Disconnected');
      }
    };

    checkApiStatus();
    const interval = setInterval(checkApiStatus, 30000); // Check every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const value = {
    apiStatus,
    apiVersion,
    apiEndpoint,
  };

  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>;
};