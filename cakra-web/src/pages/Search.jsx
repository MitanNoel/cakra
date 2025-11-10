import React, { useState, useMemo } from 'react';
import { Helmet } from 'react-helmet';
import { motion } from 'framer-motion';
import { Search as SearchIcon, Filter, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import DataGrid from '@/components/DataGrid';
import ExportModal from '@/components/ExportModal';
import ManualAnalysis from '@/components/ManualAnalysis';
import { mockCrawlData } from '@/utils/mockData';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';

const categories = [
  { id: 'gambling', label: 'Gambling' },
  { id: 'scam', label: 'Scam/Fraud' },
  { id: 'defacement', label: 'Defacement' },
  { id: 'harmful', label: 'Harmful Content' },
  { id: 'pornography', label: 'Pornography' },
  { id: 'violence', label: 'Violence/Extremism' },
  { id: 'drugs', label: 'Drugs' },
  { id: 'phishing', label: 'Phishing/Malware' },
];
const extensions = ['.ac.id', '.com.id', '.co.id', '.xyz', '.net', '.org'];
const operators = ['ISP1', 'ISP2', 'ISP3', 'ISP4'];
const statuses = ['success', 'failed', 'retried'];
const entities = [
  { id: 'bank', label: 'Bank Account' },
  { id: 'qris', label: 'QRIS' },
  { id: 'ewallet', label: 'E-Wallet' },
  { id: 'phone', label: 'Phone Number' }
];

const Search = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState({
    extensions: [],
    categories: [],
    operator: '',
    status: '',
    entities: [],
  });
  const [isFilterVisible, setIsFilterVisible] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const navigate = useNavigate();

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const handleMultiSelectChange = (key, value) => {
    setFilters(prev => {
      const current = prev[key] || [];
      const newValues = current.includes(value)
        ? current.filter(v => v !== value)
        : [...current, value];
      return { ...prev, [key]: newValues };
    });
  };

  const filteredData = useMemo(() => {
    let filtered = mockCrawlData;

    if (searchQuery) {
      const searchLower = searchQuery.toLowerCase();
      filtered = filtered.filter(item =>
        item.domain.toLowerCase().includes(searchLower) ||
        item.kategori.toLowerCase().includes(searchLower) ||
        item.operator_hosting.toLowerCase().includes(searchLower) ||
        item.entities_detected.some(entity => entity.toLowerCase().includes(searchLower))
      );
    }

    if (filters.extensions.length > 0) {
      filtered = filtered.filter(item => filters.extensions.some(ext => item.domain.endsWith(ext)));
    }
    if (filters.categories.length > 0) {
      filtered = filtered.filter(item => filters.categories.includes(item.kategori));
    }
    if (filters.operator) {
      filtered = filtered.filter(item => item.operator_hosting === filters.operator);
    }
    if (filters.status) {
      filtered = filtered.filter(item => item.status === filters.status);
    }
    if (filters.entities.length > 0) {
      filtered = filtered.filter(item => filters.entities.some(entityType => 
        item.entities_detected.some(entity => entity.toLowerCase().startsWith(entityType))
      ));
    }

    return filtered;
  }, [searchQuery, filters]);

  const handleRowClick = (row) => {
    navigate(`/analysis/${row.domain}`);
  };

  return (
    <>
      <Helmet>
        <title>Search - C.A.K.R.A Investigation</title>
        <meta name="description" content="Search dan filter data crawling domain untuk investigasi" />
      </Helmet>
      
      <div className="space-y-6">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          <h1 className="text-3xl font-bold text-white mb-2">Search & Analysis</h1>
          <p className="text-gray-300">Investigate domains and perform manual analysis.</p>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.1 }}>
          <ManualAnalysis />
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.2 }} className="space-y-4">
          <div className="flex space-x-4">
            <div className="flex-1 relative">
              <SearchIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input placeholder="Search database (domain, keyword, account, QRIS...)" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="pl-10" />
            </div>
            <Button onClick={() => setIsFilterVisible(!isFilterVisible)} variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              <span>{isFilterVisible ? 'Hide' : 'Show'} Filters</span>
            </Button>
          </div>

          {isFilterVisible && (
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="glass-effect p-4 rounded-lg border border-white/10 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-300 block mb-2">Domain Extension</label>
                  <div className="flex flex-wrap gap-2">
                    {extensions.map(ext => (
                      <button key={ext} onClick={() => handleMultiSelectChange('extensions', ext)} className={`px-2 py-1 text-xs rounded-full border transition-colors ${filters.extensions.includes(ext) ? 'bg-purple-500 border-purple-500 text-white' : 'bg-transparent border-gray-600 hover:bg-gray-700'}`}>{ext}</button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-300 block mb-2">Category</label>
                  <Select onValueChange={(value) => handleMultiSelectChange('categories', value)}>
                    <SelectTrigger><SelectValue placeholder="Select categories..." /></SelectTrigger>
                    <SelectContent>
                      {categories.map(cat => <SelectItem key={cat.id} value={cat.id}><div className="flex items-center"><Checkbox checked={filters.categories.includes(cat.id)} className="mr-2" />{cat.label}</div></SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-300 block mb-2">Operator/Hosting</label>
                  <Select value={filters.operator} onValueChange={(value) => handleFilterChange('operator', value)}>
                    <SelectTrigger><SelectValue placeholder="Select operator..." /></SelectTrigger>
                    <SelectContent>{operators.map(op => <SelectItem key={op} value={op}>{op}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-300 block mb-2">Status</label>
                  <Select value={filters.status} onValueChange={(value) => handleFilterChange('status', value)}>
                    <SelectTrigger><SelectValue placeholder="Select status..." /></SelectTrigger>
                    <SelectContent>{statuses.map(st => <SelectItem key={st} value={st}>{st.charAt(0).toUpperCase() + st.slice(1)}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
              </div>
            </motion.div>
          )}

          <div className="flex items-center justify-between text-sm text-gray-300">
            <span>Showing {filteredData.length} of {mockCrawlData.length} results</span>
            <Button onClick={() => setIsExportModalOpen(true)} variant="outline" size="sm" disabled={filteredData.length === 0}>Export Results</Button>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.3 }}>
          <DataGrid data={filteredData} onRowClick={handleRowClick} showSelection={true} />
        </motion.div>
      </div>

      <ExportModal isOpen={isExportModalOpen} onClose={() => setIsExportModalOpen(false)} data={mockCrawlData} filteredData={filteredData} />
    </>
  );
};

export default Search;