export const mockCrawlData = [
  {
    id: 1,
    domain: "xyzslot.xyz",
    kategori: "gambling",
    confidence: 0.92,
    operator_hosting: "ISP1",
    crawl_timestamp: "2025-09-22T12:00:00Z",
    status: "success",
    entities_detected: ["QRIS:1234567890"],
    structured_judgment: {
      illegal_rate: 90,
      status: "Malicious",
      domain_ip: "103.224.182.210",
      server_version: "nginx/1.18.0",
      weaknesses: ["Outdated Nginx", "XSS"],
      defacement_detected: false,
      suspicious_scripts: ["/js/spin-wheel.js", "/js/payment-gateway.js"],
      recommendations: ["Block domain and IP", "Investigate payment gateway", "Scan for further vulnerabilities"]
    }
  },
  {
    id: 2,
    domain: "frauddeal.net",
    kategori: "scam",
    confidence: 0.87,
    operator_hosting: "ISP2",
    crawl_timestamp: "2025-09-22T12:15:00Z",
    status: "success",
    entities_detected: ["Bank:987654321"],
    structured_judgment: {
      illegal_rate: 85,
      status: "Malicious",
      domain_ip: "192.168.1.1",
      server_version: "Apache/2.4.41",
      weaknesses: ["SQLi"],
      defacement_detected: false,
      suspicious_scripts: ["/js/checkout.js"],
      recommendations: ["Block domain", "Report bank account to authorities"]
    }
  },
  {
    id: 3,
    domain: "hacked-gov.com.id",
    kategori: "defacement",
    confidence: 0.98,
    operator_hosting: "ISP3",
    crawl_timestamp: "2025-09-21T11:30:00Z",
    status: "success",
    entities_detected: [],
    structured_judgment: {
      illegal_rate: 95,
      status: "Malicious",
      domain_ip: "10.0.0.1",
      server_version: "IIS/10.0",
      weaknesses: ["CSRF", "Outdated IIS"],
      defacement_detected: true,
      suspicious_scripts: ["/hacked.js"],
      recommendations: ["Isolate server", "Perform forensic analysis", "Patch vulnerabilities"]
    }
  },
  {
    id: 4,
    domain: "pornhub-clone.xyz",
    kategori: "pornography",
    confidence: 0.99,
    operator_hosting: "ISP1",
    crawl_timestamp: "2025-09-21T10:00:00Z",
    status: "success",
    entities_detected: [],
    structured_judgment: {
      illegal_rate: 100,
      status: "Malicious",
      domain_ip: "203.0.113.10",
      server_version: "LiteSpeed",
      weaknesses: [],
      defacement_detected: false,
      suspicious_scripts: ["/js/video-player.js"],
      recommendations: ["Block domain immediately", "Report to authorities"]
    }
  },
  {
    id: 5,
    domain: "extremist-forum.net",
    kategori: "violence",
    confidence: 0.85,
    operator_hosting: "ISP4",
    crawl_timestamp: "2025-09-20T09:20:00Z",
    status: "failed",
    entities_detected: [],
    structured_judgment: {
      illegal_rate: 80,
      status: "Malicious",
      domain_ip: "198.51.100.5",
      server_version: "Apache/2.4.52",
      weaknesses: [],
      defacement_detected: false,
      suspicious_scripts: [],
      recommendations: ["Monitor for activity", "Report to law enforcement"]
    }
  },
  {
    id: 6,
    domain: "drug-market.org",
    kategori: "drugs",
    confidence: 0.91,
    operator_hosting: "ISP2",
    crawl_timestamp: "2025-09-20T08:00:00Z",
    status: "success",
    entities_detected: ["E-wallet:081234567890"],
    structured_judgment: {
      illegal_rate: 92,
      status: "Malicious",
      domain_ip: "198.51.100.22",
      server_version: "nginx/1.21.0",
      weaknesses: [],
      defacement_detected: false,
      suspicious_scripts: ["/js/cart.js"],
      recommendations: ["Block domain", "Investigate e-wallet transactions"]
    }
  },
  {
    id: 7,
    domain: "bank-phishing.com.id",
    kategori: "phishing",
    confidence: 0.96,
    operator_hosting: "ISP3",
    crawl_timestamp: "2025-09-19T15:30:00Z",
    status: "success",
    entities_detected: ["Phone:087654321098"],
    structured_judgment: {
      illegal_rate: 98,
      status: "Malicious",
      domain_ip: "192.0.2.14",
      server_version: "Apache/2.2.15",
      weaknesses: ["Outdated Apache"],
      defacement_detected: false,
      suspicious_scripts: ["/login.js"],
      recommendations: ["Take down site immediately", "Warn public", "Blacklist domain"]
    }
  },
  {
    id: 8,
    domain: "safe-news.ac.id",
    kategori: "news",
    confidence: 0.1,
    operator_hosting: "ISP1",
    crawl_timestamp: "2025-09-19T14:00:00Z",
    status: "success",
    entities_detected: [],
    structured_judgment: {
      illegal_rate: 5,
      status: "Safe",
      domain_ip: "1.1.1.1",
      server_version: "nginx/1.22.0",
      weaknesses: [],
      defacement_detected: false,
      suspicious_scripts: [],
      recommendations: ["No action needed"]
    }
  }
];

export const mockMetrics = {
  totalDomains: 1247,
  flaggedCategories: 8,
  successRate: 94.2,
  todaysCrawls: 156
};

export const mockChartData = {
  crawlTrend: [
    { date: '2025-09-16', crawls: 120 },
    { date: '2025-09-17', crawls: 135 },
    { date: '2025-09-18', crawls: 98 },
    { date: '2025-09-19', crawls: 167 },
    { date: '2025-09-20', crawls: 142 },
    { date: '2025-09-21', crawls: 189 },
    { date: '2025-09-22', crawls: 156 }
  ],
  categoryDistribution: [
    { name: 'Gambling', value: 35, color: '#8B5CF6', description: 'Situs judi online, taruhan ilegal.' },
    { name: 'Scam/Fraud', value: 28, color: '#EF4444', description: 'Penipuan, investasi bodong.' },
    { name: 'Pornography', value: 25, color: '#EC4899', description: 'Konten dewasa eksplisit.' },
    { name: 'Phishing', value: 22, color: '#F59E0B', description: 'Pencurian data kredensial.' },
    { name: 'Defacement', value: 10, color: '#10B981', description: 'Peretasan tampilan situs.' },
    { name: 'Harmful', value: 8, color: '#6B7280', description: 'Konten berbahaya lainnya.' },
    { name: 'Violence', value: 5, color: '#991B1B', description: 'Konten kekerasan & ekstrimisme.' },
    { name: 'Drugs', value: 3, color: '#CA8A04', description: 'Perdagangan obat-obatan terlarang.' }
  ]
};