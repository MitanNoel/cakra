// Transform backend API response to frontend expected format
export const transformScanResult = (apiResult) => {
  // Handle both single result and array of results
  if (Array.isArray(apiResult)) {
    return apiResult.map(transformSingleResult);
  }
  return transformSingleResult(apiResult);
};

const transformSingleResult = (apiResult) => {
  const contentAnalysis = apiResult.content_analysis || {};
  const paymentAnalysis = apiResult.payment_analysis || {};
  const networkAnalysis = apiResult.network_analysis || {};
  const scoutAnalysis = apiResult.scout_analysis || {};

  const confidence = contentAnalysis.confidence || 0;
  const illegalRate = contentAnalysis.illegal_rate ?? apiResult.risk_score ?? 0;

  return {
    id: apiResult.id || Date.now(),
    domain: apiResult.domain || apiResult.url || '',
    kategori: contentAnalysis.category || 'unknown',
    confidence: (confidence || 0) / 100,
    operator_hosting: networkAnalysis.operator || 'Unknown',
    crawl_timestamp: apiResult.timestamp || new Date().toISOString(),
    status: apiResult.error ? 'failed' : 'success',
    entities_detected: (paymentAnalysis.payment_channels || []).map(ch =>
      `${ch.type || 'Unknown'}:${ch.identifier || ''}`
    ),
    structured_judgment: {
      illegal_rate: illegalRate,
      status: illegalRate > 50 ? 'Malicious' : 'Safe',
      domain_ip: networkAnalysis.ip || 'Unknown',
      server_version: networkAnalysis.server_version || 'Unknown',
      weaknesses: scoutAnalysis.weaknesses || [],
      defacement_detected: contentAnalysis.defacement_detected || false,
      suspicious_scripts: scoutAnalysis.suspicious_scripts || 0,
      recommendations: Array.isArray(apiResult.report?.recommendations)
        ? apiResult.report.recommendations
        : ['Monitor this domain', 'Block if confirmed malicious']
    }
  };
};

export const transformStatistics = (apiStats) => {
  return {
    totalDomains: apiStats.total_scans || 0,
    flaggedCategories: apiStats.threats_detected || 0,
    successRate: apiStats.success_rate || 0,
    todaysCrawls: apiStats.recent_scans || 0
  };
};

export const transformChartData = (results = []) => {
  const categoryCount = {};
  const dateCount = {};

  results.forEach(result => {
    const category = result.kategori || 'unknown';
    categoryCount[category] = (categoryCount[category] || 0) + 1;

    const timestamp = result.crawl_timestamp || result.timestamp || new Date().toISOString();
    const date = new Date(timestamp).toISOString().split('T')[0];
    dateCount[date] = (dateCount[date] || 0) + 1;
  });

  return {
    categoryDistribution: Object.entries(categoryCount).map(([name, value]) => ({
      name,
      value,
      color: getCategoryColor(name)
    })),
    crawlTrend: Object.entries(dateCount)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, crawls]) => ({
        date,
        crawls
      }))
  };
};

const getCategoryColor = (category) => {
  const colors = {
    gambling: '#8B5CF6',
    scam: '#EF4444',
    defacement: '#F59E0B',
    harmful: '#EC4899',
    phishing: '#06B6D4',
    unknown: '#6B7280'
  };
  return colors[category] || colors.unknown;
};