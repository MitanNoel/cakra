import React, { useState, useEffect } from 'react';
import { Helmet } from 'react-helmet';
import { motion } from 'framer-motion';
import { AreaChart, Area, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Shield, AlertTriangle, TrendingUp, Download, Eye, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import MetricCard from '@/components/MetricCard';
import DataGrid from '@/components/DataGrid';
import ExportModal from '@/components/ExportModal';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { transformScanResult, transformStatistics, transformChartData } from '@/utils/dataTransformers';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="glass-effect p-3 rounded-lg border border-white/10">
        <p className="font-bold text-white">{data.name}</p>
        <p className="text-sm text-gray-300">{`Count: ${data.value}`}</p>
        <p className="text-xs text-gray-400 mt-1">{data.description}</p>
      </div>
    );
  }
  return null;
};

const Dashboard = () => {
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [crawlData, setCrawlData] = useState([]);
  const [metrics, setMetrics] = useState({
    totalDomains: 0,
    flaggedCategories: 0,
    successRate: 0,
    todaysCrawls: 0
  });
  const [chartData, setChartData] = useState({
    categoryDistribution: [],
    crawlTrend: []
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);

        const [resultsResponse, statsResponse] = await Promise.allSettled([
          api.getScanResults({ limit: 10, days_back: 7 }),
          api.getStatistics()
        ]);

        let transformedResults = [];
        if (resultsResponse.status === 'fulfilled') {
          transformedResults = transformScanResult(resultsResponse.value);
        }

        let transformedStats = metrics;
        if (statsResponse.status === 'fulfilled') {
          transformedStats = transformStatistics(statsResponse.value);
        }

        const transformedCharts = transformChartData(transformedResults);

        setCrawlData(transformedResults);
        setMetrics(transformedStats);
        setChartData(transformedCharts);

      } catch (err) {
        setError(err.message || 'Failed to load dashboard data');
        console.error('Dashboard data fetch error:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleRowClick = (row) => {
    navigate(`/analysis/${row.domain}`);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-purple-400" />
          <p className="text-gray-300">Loading dashboard data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <AlertTriangle className="h-8 w-8 mx-auto mb-4 text-red-400" />
          <p className="text-red-400 mb-4">Error loading dashboard: {error}</p>
          <Button onClick={() => window.location.reload()} variant="outline">
            Retry
          </Button>
        </div>
      </div>
    );
  }

  return (
    <>
      <Helmet>
        <title>Dashboard - C.A.K.R.A Investigation</title>
        <meta name="description" content="Dashboard overview untuk monitoring dan analisis domain investigation" />
      </Helmet>
      
      <div className="space-y-8">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
          <p className="text-gray-300">Monitor and analyze domain crawling activities.</p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <MetricCard title="Total Domains" value={metrics.totalDomains.toLocaleString()} subtitle="Domains detected" icon={Shield} delay={0.1} />
          <MetricCard title="Flagged Categories" value={metrics.flaggedCategories} subtitle="Active categories" icon={AlertTriangle} delay={0.2} />
          <MetricCard title="Success Rate" value={`${metrics.successRate}%`} subtitle="Crawling success" icon={TrendingUp} delay={0.3} />
          <MetricCard title="Today's Crawls" value={metrics.todaysCrawls} subtitle="New crawls today" icon={Eye} delay={0.4} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          <motion.div className="lg:col-span-3" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.5, delay: 0.5 }}>
            <Card>
              <CardHeader><CardTitle>Crawling Trend (7 Days)</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={chartData.crawlTrend}>
                    <defs><linearGradient id="crawlGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.8}/><stop offset="95%" stopColor="#8B5CF6" stopOpacity={0.1}/></linearGradient></defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="date" stroke="#9CA3AF" fontSize={12} tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} />
                    <YAxis stroke="#9CA3AF" fontSize={12} />
                    <Tooltip contentStyle={{ backgroundColor: 'rgba(17, 24, 39, 0.9)', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '8px' }} />
                    <Area type="monotone" dataKey="crawls" stroke="#8B5CF6" fillOpacity={1} fill="url(#crawlGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div className="lg:col-span-2" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.5, delay: 0.6 }}>
            <Card>
              <CardHeader><CardTitle>Category Distribution</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie data={chartData.categoryDistribution} cx="50%" cy="50%" innerRadius={60} outerRadius={100} paddingAngle={5} dataKey="value" nameKey="name">
                      {chartData.categoryDistribution.map((entry, index) => (<Cell key={`cell-${index}`} fill={entry.color} />))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                    <Legend iconSize={10} layout="vertical" verticalAlign="middle" align="right" />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>
        </div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.7 }}>
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Recent Crawls</CardTitle>
                <Button onClick={() => setIsExportModalOpen(true)} className="galaxy-gradient-button hover:galaxy-gradient-button">
                  <Download className="h-4 w-4 mr-2" />
                  Export All CSV
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <DataGrid data={crawlData} onRowClick={handleRowClick} showSelection={false} />
            </CardContent>
          </Card>
        </motion.div>

        <ExportModal isOpen={isExportModalOpen} onClose={() => setIsExportModalOpen(false)} data={crawlData} />
      </div>
    </>
  );
};

export default Dashboard;