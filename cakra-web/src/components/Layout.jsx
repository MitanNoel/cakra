import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Download } from 'lucide-react';
import ApiInfo from '@/components/ApiInfo';
import ExportModal from '@/components/ExportModal';
import { mockCrawlData } from '@/utils/mockData';

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/search', label: 'Search' },
  { path: '/analysis', label: 'Analysis' },
];

const Header = () => {
  const location = useLocation();
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);

  return (
    <>
      <header className="glass-effect border-b border-white/10 p-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center space-x-8">
          <Link to="/" className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-purple-400" />
            <span className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-purple-600 bg-clip-text text-transparent">
              C.A.K.R.A
            </span>
          </Link>
          <nav className="flex items-center space-x-4">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
              
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`px-3 py-2 rounded-md transition-all text-base font-medium ${
                    isActive
                      ? 'text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {item.label}
                  {isActive && (
                    <motion.div className="h-0.5 bg-purple-500 mt-1" layoutId="underline" />
                  )}
                </Link>
              );
            })}
             <button
              onClick={() => setIsExportModalOpen(true)}
              className="flex items-center space-x-2 px-3 py-2 rounded-md transition-all text-base font-medium text-gray-400 hover:text-white"
            >
              <Download className="h-5 w-5" />
              <span>Export</span>
            </button>
          </nav>
        </div>
        <ApiInfo />
      </header>
      <ExportModal isOpen={isExportModalOpen} onClose={() => setIsExportModalOpen(false)} data={mockCrawlData} />
    </>
  );
};

const Layout = ({ children }) => {
  return (
    <div className="min-h-screen flex flex-col galaxy-gradient">
      <Header />
      <main className="flex-1">
        <motion.div
          key={useLocation().pathname}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.4 }}
          className="p-8"
        >
          {children}
        </motion.div>
      </main>
    </div>
  );
};

export default Layout;