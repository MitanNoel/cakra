import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Slider } from '@/components/ui/slider';
import { Filter, RotateCcw, X } from 'lucide-react';

const FilterPanel = ({ onFiltersChange, isOpen, onToggle }) => {
  const [filters, setFilters] = useState({
    domain: '',
    domainFilter: 'subdomain',
    extension: '',
    categories: [],
    confidence: [0],
    confidencePreset: 'low',
    dateRange: { start: '', end: '' },
    operator: '',
    status: '',
    entities: []
  });

  const categories = [
    { id: 'gambling', label: 'Gambling' },
    { id: 'fraud', label: 'Fraud' },
    { id: 'scam', label: 'Scam' },
    { id: 'defacement', label: 'Defacement' },
    { id: 'harmful', label: 'Harmful' }
  ];

  const entities = [
    { id: 'bank', label: 'Bank Account' },
    { id: 'qris', label: 'QRIS' },
    { id: 'ewallet', label: 'E-Wallet' },
    { id: 'phone', label: 'Phone Number' }
  ];

  const operators = ['ISP1', 'ISP2', 'ISP3', 'ISP4'];
  const statuses = ['success', 'failed', 'retried'];
  const extensions = ['.ac.id', '.com.id', '.co.id', '.xyz', '.net', '.org'];

  const handleFilterChange = (key, value) => {
    const newFilters = { ...filters, [key]: value };
    setFilters(newFilters);
    onFiltersChange(newFilters);
  };

  const handleCategoryChange = (categoryId, checked) => {
    const newCategories = checked
      ? [...filters.categories, categoryId]
      : filters.categories.filter(id => id !== categoryId);
    handleFilterChange('categories', newCategories);
  };

  const handleEntityChange = (entityId, checked) => {
    const newEntities = checked
      ? [...filters.entities, entityId]
      : filters.entities.filter(id => id !== entityId);
    handleFilterChange('entities', newEntities);
  };

  const handleConfidencePreset = (preset) => {
    const presetValues = {
      low: [0],
      medium: [0.5],
      high: [0.8]
    };
    handleFilterChange('confidence', presetValues[preset]);
    handleFilterChange('confidencePreset', preset);
  };

  const resetFilters = () => {
    const defaultFilters = {
      domain: '',
      domainFilter: 'subdomain',
      extension: '',
      categories: [],
      confidence: [0],
      confidencePreset: 'low',
      dateRange: { start: '', end: '' },
      operator: '',
      status: '',
      entities: []
    };
    setFilters(defaultFilters);
    onFiltersChange(defaultFilters);
  };

  if (!isOpen) {
    return (
      <Button
        onClick={onToggle}
        variant="outline"
        className="fixed left-4 top-1/2 transform -translate-y-1/2 z-40"
      >
        <Filter className="h-4 w-4" />
      </Button>
    );
  }

  return (
    <motion.div
      initial={{ x: -300, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: -300, opacity: 0 }}
      transition={{ duration: 0.3 }}
      className="w-80 space-y-4"
    >
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg">Filters</CardTitle>
            <div className="flex space-x-2">
              <Button onClick={resetFilters} variant="ghost" size="icon"><RotateCcw className="h-4 w-4" /></Button>
              <Button onClick={onToggle} variant="ghost" size="icon"><X className="h-4 w-4" /></Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6 max-h-[calc(100vh-200px)] overflow-y-auto pr-2">
          <div className="space-y-2">
            <label className="text-sm font-medium">Domain</label>
            <Input placeholder="Search domain..." value={filters.domain} onChange={(e) => handleFilterChange('domain', e.target.value)} />
            <div className="flex space-x-2">
              <Select value={filters.domainFilter} onValueChange={(value) => handleFilterChange('domainFilter', value)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="exact">Exact</SelectItem><SelectItem value="subdomain">Subdomain</SelectItem></SelectContent>
              </Select>
              <Select value={filters.extension} onValueChange={(value) => handleFilterChange('extension', value)}>
                <SelectTrigger><SelectValue placeholder="Ext" /></SelectTrigger>
                <SelectContent>{extensions.map((ext) => <SelectItem key={ext} value={ext}>{ext}</SelectItem>)}</SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Content Categories</label>
            <div className="space-y-2">{categories.map((category) => (<div key={category.id} className="flex items-center space-x-2"><Checkbox id={category.id} checked={filters.categories.includes(category.id)} onCheckedChange={(checked) => handleCategoryChange(category.id, checked)} /><label htmlFor={category.id} className="text-sm">{category.label}</label></div>))}</div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Confidence Level</label>
            <div className="flex space-x-2 mb-2">{['low', 'medium', 'high'].map((preset) => (<Button key={preset} variant={filters.confidencePreset === preset ? 'default' : 'outline'} size="sm" onClick={() => handleConfidencePreset(preset)} className={filters.confidencePreset === preset ? 'galaxy-gradient-button' : ''}>{preset.charAt(0).toUpperCase() + preset.slice(1)}</Button>))}</div>
            <Slider value={filters.confidence} onValueChange={(value) => handleFilterChange('confidence', value)} max={1} min={0} step={0.01} className="w-full" />
            <div className="text-xs text-gray-400">Min Confidence: {(filters.confidence[0] * 100).toFixed(0)}%</div>
          </div>

          {/* <div className="space-y-2">
          <label className="text-sm font-medium">Confidence Level</label>
          <div className="flex space-x-2">
            {[
              { key: "low", label: "Low", percent: "<30%", value: 0.3 },
              { key: "medium", label: "Medium", percent: "30–60%", value: 0.6 },
              { key: "high", label: "High", percent: ">60%", value: 1 },
            ].map((preset) => (
              <Button
                key={preset.key}
                variant={filters.confidencePreset === preset.key ? "default" : "outline"}
                size="sm"
                onClick={() => {
                  handleConfidencePreset(preset.key);
                  handleFilterChange("confidence", [preset.value]);
                }}
                className={filters.confidencePreset === preset.key ? "galaxy-gradient-button" : ""}
              >
                {preset.label}
              </Button>
            ))}
          </div>

          <div className="text-xs text-gray-400">
            {filters.confidencePreset === "low" && "Confidence < 30%"}
            {filters.confidencePreset === "medium" && "Confidence 30–60%"}
            {filters.confidencePreset === "high" && "Confidence > 60%"}
          </div>
        </div> */}

          <div className="space-y-2">
            <label className="text-sm font-medium">Crawl Date Range</label>
            <div className="grid grid-cols-2 gap-2"><Input type="date" value={filters.dateRange.start} onChange={(e) => handleFilterChange('dateRange', { ...filters.dateRange, start: e.target.value })} /><Input type="date" value={filters.dateRange.end} onChange={(e) => handleFilterChange('dateRange', { ...filters.dateRange, end: e.target.value })} /></div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Operator/Hosting</label>
            <Select value={filters.operator} onValueChange={(value) => handleFilterChange('operator', value)}><SelectTrigger><SelectValue placeholder="Select operator..." /></SelectTrigger><SelectContent>{operators.map((operator) => (<SelectItem key={operator} value={operator}>{operator}</SelectItem>))}</SelectContent></Select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Crawl Status</label>
            <Select value={filters.status} onValueChange={(value) => handleFilterChange('status', value)}><SelectTrigger><SelectValue placeholder="Select status..." /></SelectTrigger><SelectContent>{statuses.map((status) => (<SelectItem key={status} value={status}>{status.charAt(0).toUpperCase() + status.slice(1)}</SelectItem>))}</SelectContent></Select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Entity Detection</label>
            <div className="space-y-2">{entities.map((entity) => (<div key={entity.id} className="flex items-center space-x-2"><Checkbox id={entity.id} checked={filters.entities.includes(entity.id)} onCheckedChange={(checked) => handleEntityChange(entity.id, checked)} /><label htmlFor={entity.id} className="text-sm">{entity.label}</label></div>))}</div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default FilterPanel;