import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Helmet } from 'react-helmet';
import Layout from '@/components/Layout';
import Dashboard from '@/pages/Dashboard';
import Search from '@/pages/Search';
import Analysis from '@/pages/Analysis';
import { Toaster } from '@/components/ui/toaster';
import { ApiProvider } from '@/hooks/useApi';

function App() {
  return (
    <>
      <Helmet>
        <title>C.A.K.R.A - Dashboard Investigasi</title>
        <meta name="description" content="Dashboard investigasi C.A.K.R.A untuk monitoring dan analisis domain" />
      </Helmet>
      <ApiProvider>
        <Router>
          <div className="min-h-screen bg-black text-white">
            <Layout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/search" element={<Search />} />
                <Route path="/analysis/:domain" element={<Analysis />} />
                <Route path="/analysis" element={<Analysis />} />
              </Routes>
            </Layout>
            <Toaster />
          </div>
        </Router>
      </ApiProvider>
    </>
  );
}

export default App;