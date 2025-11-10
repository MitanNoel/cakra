import Papa from 'papaparse';

export const exportToCSV = (data, filename = 'cakra-export', selectedColumns = null) => {
  const timestamp = new Date().toISOString();
  const systemVersion = '1.0.0';
  
  // Default columns if none selected
  const defaultColumns = [
    'domain',
    'kategori', 
    'confidence',
    'operator_hosting',
    'crawl_timestamp',
    'status',
    'entities_detected'
  ];
  
  const columnsToExport = selectedColumns || defaultColumns;
  
  // Filter data to only include selected columns
  const filteredData = data.map(row => {
    const filteredRow = {};
    columnsToExport.forEach(col => {
      if (col === 'entities_detected' && Array.isArray(row[col])) {
        filteredRow[col] = row[col].join('; ');
      } else {
        filteredRow[col] = row[col];
      }
    });
    return filteredRow;
  });
  
  // Add metadata header
  const metadata = [
    ['# CAKRA Investigation Dashboard Export'],
    ['# Exported by: System'],
    [`# Timestamp: ${timestamp}`],
    [`# System Version: ${systemVersion}`],
    [`# Total Records: ${data.length}`],
    [''],
    []
  ];
  
  // Convert to CSV
  const csv = Papa.unparse(filteredData, {
    header: true,
    skipEmptyLines: true
  });
  
  // Combine metadata with CSV
  const metadataText = metadata.map(row => row.join(',')).join('\n');
  const finalCSV = metadataText + '\n' + csv;
  
  // Download file
  const blob = new Blob([finalCSV], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  
  link.setAttribute('href', url);
  link.setAttribute('download', `${filename}-${timestamp.split('T')[0]}.csv`);
  link.style.visibility = 'hidden';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  
  return {
    success: true,
    filename: `${filename}-${timestamp.split('T')[0]}.csv`,
    recordCount: data.length
  };
};