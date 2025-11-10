const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const api = {
  async getScanResults(params = {}) {
    const query = new URLSearchParams(params);
    const response = await fetch(`${API_BASE_URL}/api/v1/scan-results?${query}`);
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    return response.json();
  },

  async getScanResult(url) {
    const response = await fetch(`${API_BASE_URL}/api/v1/scan-results/${encodeURIComponent(url)}`);
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    return response.json();
  },

  async scanUrl(url) {
    const response = await fetch(`${API_BASE_URL}/api/v1/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ url })
    });
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    return response.json();
  },

  async getStatistics() {
    const response = await fetch(`${API_BASE_URL}/api/v1/statistics`);
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    return response.json();
  },

  async getPaymentChannels(params = {}) {
    const query = new URLSearchParams(params);
    const response = await fetch(`${API_BASE_URL}/api/v1/payment-channels?${query}`);
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    return response.json();
  }
};