import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Download, FileText } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';
import { exportToCSV } from '@/utils/csvExport';

const ExportModal = ({ isOpen, onClose, data, filteredData, selectedDomain }) => {
  const [exportScope, setExportScope] = useState('all');
  const [selectedColumns, setSelectedColumns] = useState([
    'domain',
    'kategori',
    'confidence',
    'operator_hosting',
    'crawl_timestamp',
    'status',
    'entities_detected'
  ]);
  const { toast } = useToast();

  const availableColumns = [
    { id: 'domain', label: 'Domain' },
    { id: 'kategori', label: 'Kategori' },
    { id: 'confidence', label: 'Confidence' },
    { id: 'operator_hosting', label: 'Operator/Hosting' },
    { id: 'crawl_timestamp', label: 'Timestamp' },
    { id: 'status', label: 'Status' },
    { id: 'entities_detected', label: 'Detected Entities' }
  ];

  const handleColumnToggle = (columnId, checked) => {
    if (checked) {
      setSelectedColumns([...selectedColumns, columnId]);
    } else {
      setSelectedColumns(selectedColumns.filter(id => id !== columnId));
    }
  };

  const getDataToExport = () => {
    switch (exportScope) {
      case 'filtered':
        return filteredData || data;
      case 'single':
        return selectedDomain ? [selectedDomain] : [];
      default:
        return data;
    }
  };

  const getPreviewCount = () => {
    const dataToExport = getDataToExport();
    return dataToExport.length;
  };

  const handleExport = () => {
    if (selectedColumns.length === 0) {
      toast({
        title: "No columns selected",
        description: "Please select at least one column to export.",
        variant: "destructive",
      });
      return;
    }

    const dataToExport = getDataToExport();
    if (dataToExport.length === 0) {
      toast({
        title: "No data to export",
        description: "There is no data available for the selected scope.",
        variant: "destructive",
      });
      return;
    }

    const filename = exportScope === 'single' 
      ? `cakra-${selectedDomain?.domain || 'single'}-analysis`
      : `cakra-${exportScope}-data`;

    const result = exportToCSV(dataToExport, filename, selectedColumns);
    
    if (result.success) {
      toast({
        title: "Export successful!",
        description: `${result.recordCount} records exported to ${result.filename}`,
      });
      onClose();
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <Dialog open={isOpen} onOpenChange={onClose}>
          <DialogContent className="sm:max-w-md glass-effect border-white/20">
            <DialogHeader>
              <DialogTitle className="flex items-center space-x-2">
                <FileText className="h-5 w-5 text-purple-400" />
                <span>Export Data</span>
              </DialogTitle>
            </DialogHeader>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-6"
            >
              {/* Export Scope */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Export Scope</label>
                <Select value={exportScope} onValueChange={setExportScope}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Results</SelectItem>
                    <SelectItem value="filtered">Filtered Results</SelectItem>
                    {selectedDomain && (
                      <SelectItem value="single">Single Domain</SelectItem>
                    )}
                  </SelectContent>
                </Select>
              </div>

              {/* Column Selection */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Columns to Export</label>
                <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
                  {availableColumns.map((column) => (
                    <div key={column.id} className="flex items-center space-x-2">
                      <Checkbox
                        id={column.id}
                        checked={selectedColumns.includes(column.id)}
                        onCheckedChange={(checked) => handleColumnToggle(column.id, checked)}
                      />
                      <label htmlFor={column.id} className="text-sm">
                        {column.label}
                      </label>
                    </div>
                  ))}
                </div>
              </div>

              {/* Preview */}
              <div className="glass-effect p-4 rounded-lg border border-white/10">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-300">Preview</span>
                  <span className="text-lg font-semibold text-purple-300">
                    {getPreviewCount()} records
                  </span>
                </div>
                <div className="text-xs text-gray-400 mt-1">
                  {selectedColumns.length} columns selected
                </div>
              </div>

              {/* Actions */}
              <div className="flex space-x-2">
                <Button
                  onClick={onClose}
                  variant="outline"
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleExport}
                  className="flex-1 galaxy-gradient-button hover:galaxy-gradient-button"
                  disabled={selectedColumns.length === 0 || getPreviewCount() === 0}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download CSV
                </Button>
              </div>
            </motion.div>
          </DialogContent>
        </Dialog>
      )}
    </AnimatePresence>
  );
};

export default ExportModal;