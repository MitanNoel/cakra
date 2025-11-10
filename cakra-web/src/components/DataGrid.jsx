import React, { useState, useMemo } from 'react';
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  flexRender,
} from '@tanstack/react-table';
import { motion } from 'framer-motion';
import { ChevronLeft, ChevronRight, ArrowUpDown, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/components/ui/use-toast';
import { exportToCSV } from '@/utils/csvExport';

const ConfidenceBadge = ({ score }) => {
  let level, color;
  if (score < 0.3) {
    level = 'Low';
    color = 'bg-green-500/20 text-green-300';
  } else if (score >= 0.3 && score <= 0.6) {
    level = 'Medium';
    color = 'bg-yellow-500/20 text-yellow-300';
  } else {
    level = 'High';
    color = 'bg-red-500/20 text-red-300';
  }
  return <span className={`px-2 py-1 rounded-full text-xs font-medium ${color}`}>{level}</span>;
};

const DataGrid = ({ data, onRowClick, showSelection = false }) => {
  const [sorting, setSorting] = useState([]);
  const [rowSelection, setRowSelection] = useState({});
  const { toast } = useToast();

  const columns = useMemo(() => {
    const baseColumns = [
      {
        id: 'select',
        header: ({ table }) => (
          <Checkbox
            checked={table.getIsAllPageRowsSelected()}
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label="Select all"
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label="Select row"
            onClick={(e) => e.stopPropagation()}
          />
        ),
        enableSorting: false,
        enableHiding: false,
      },
      {
        accessorKey: 'domain',
        header: ({ column }) => (
          <Button
            variant="ghost"
            onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
            className="text-left p-0 hover:bg-transparent"
          >
            Domain/URL
            <ArrowUpDown className="ml-2 h-4 w-4" />
          </Button>
        ),
        cell: ({ row }) => (
          <span className="font-medium text-purple-300">{row.getValue('domain')}</span>
        ),
      },
      {
        accessorKey: 'kategori',
        header: 'Category',
      },
      {
        accessorKey: 'confidence',
        header: ({ column }) => (
          <Button
            variant="ghost"
            onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
            className="text-left p-0 hover:bg-transparent"
          >
            Confidence
            <ArrowUpDown className="ml-2 h-4 w-4" />
          </Button>
        ),
        cell: ({ row }) => <ConfidenceBadge score={row.getValue('confidence')} />,
      },
      {
        accessorKey: 'crawl_timestamp',
        header: ({ column }) => (
          <Button
            variant="ghost"
            onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
            className="text-left p-0 hover:bg-transparent"
          >
            Last Crawl
            <ArrowUpDown className="ml-2 h-4 w-4" />
          </Button>
        ),
        cell: ({ row }) => {
          const timestamp = new Date(row.getValue('crawl_timestamp'));
          return (
            <span className="text-sm text-gray-300">
              {timestamp.toLocaleDateString()}
            </span>
          );
        },
      },
    ];

    return showSelection ? baseColumns : baseColumns.slice(1);
  }, [showSelection]);

  const table = useReactTable({
    data,
    columns,
    onSortingChange: setSorting,
    onRowSelectionChange: setRowSelection,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    state: {
      sorting,
      rowSelection,
    },
  });

  const handleExportSelected = () => {
    const selectedRows = table.getFilteredSelectedRowModel().rows;
    if (selectedRows.length === 0) {
      toast({
        title: "No data selected",
        description: "Please select at least one row to export.",
        variant: "destructive",
      });
      return;
    }

    const selectedData = selectedRows.map(row => row.original);
    const result = exportToCSV(selectedData, 'cakra-selected-data');
    
    if (result.success) {
      toast({
        title: "Export successful!",
        description: `${result.recordCount} records exported to ${result.filename}`,
      });
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="space-y-4"
    >
      {showSelection && Object.keys(rowSelection).length > 0 && (
        <div className="flex items-center justify-between p-4 glass-effect rounded-lg">
          <span className="text-sm text-gray-300">
            {Object.keys(rowSelection).length} row(s) selected
          </span>
          <Button
            onClick={handleExportSelected}
            className="galaxy-gradient-button hover:galaxy-gradient-button"
            size="sm"
          >
            <Download className="h-4 w-4 mr-2" />
            Export Selected
          </Button>
        </div>
      )}

      <div className="glass-effect rounded-lg border border-white/10 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id} className="border-b border-white/10">
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      className="px-4 py-3 text-left text-sm font-medium text-gray-300"
                    >
                      {header.isPlaceholder
                        ? null
                        : flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows?.length ? (
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    data-state={row.getIsSelected() && "selected"}
                    className="border-b border-white/5 hover:bg-white/5 transition-colors cursor-pointer data-[state=selected]:bg-purple-900/50"
                    onClick={() => onRowClick && onRowClick(row.original)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-4 py-3 text-sm">
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext()
                        )}
                      </td>
                    ))}
                  </tr>
                ))
              ) : (
                <tr>
                  <td
                    colSpan={columns.length}
                    className="px-4 py-8 text-center text-gray-400"
                  >
                    No results found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between px-4 py-3 border-t border-white/10">
          <div className="flex items-center space-x-2">
            <p className="text-sm text-gray-400">
              Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
            </p>
          </div>
          
          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default DataGrid;