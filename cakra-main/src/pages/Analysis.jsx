import React, { useState, useMemo } from 'react';
import { Helmet } from 'react-helmet';
import { motion } from 'framer-motion';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Download, ShieldCheck, AlertOctagon, Server, Code, Bug, DoorOpen, ChevronDown, ChevronUp } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import ExportModal from '@/components/ExportModal';
import { mockCrawlData } from '@/utils/mockData';

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
  return <span className={`px-2 py-1 rounded-full text-xs font-medium ${color}`}>{level} ({(score * 100).toFixed(0)}%)</span>;
};

const Analysis = () => {
  const { domain } = useParams();
  const navigate = useNavigate();
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [isRecommendationsOpen, setRecommendationsOpen] = useState(false);

  const domainData = useMemo(() => mockCrawlData.find(item => item.domain === domain), [domain]);

  if (!domain) {
    return (
      <div className="text-center">
        <h1 className="text-2xl font-bold text-white mb-4">Analysis Page</h1>
        <p className="text-gray-300 mb-6">Please select a domain from the Search page to see its analysis.</p>
        <Button onClick={() => navigate('/search')} variant="outline"><ArrowLeft className="h-4 w-4 mr-2" />Back to Search</Button>
      </div>
    );
  }

  if (!domainData) {
    return (
      <div className="text-center">
        <h1 className="text-2xl font-bold text-white mb-4">Domain Not Found</h1>
        <p className="text-gray-300 mb-6">The requested domain <span className="font-bold text-purple-300">{domain}</span> could not be found.</p>
        <Button onClick={() => navigate('/search')} variant="outline"><ArrowLeft className="h-4 w-4 mr-2" />Back to Search</Button>
      </div>
    );
  }

  const judgment = domainData.structured_judgment;

  return (
    <>
      <Helmet>
        <title>{`Analysis - ${domain} - C.A.K.R.A`}</title>
        <meta name="description" content={`Detailed analysis for domain ${domain}`} />
      </Helmet>
      
      <div className="space-y-8">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }} className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white">Structured Judgment</h1>
            <p className="text-gray-300">Analysis for <span className="font-bold text-purple-300">{domain}</span></p>
          </div>
          <div className="flex items-center space-x-2">
            <Button onClick={() => setIsExportModalOpen(true)} className="galaxy-gradient-button hover:galaxy-gradient-button" size="sm"><Download className="h-4 w-4 mr-2" />Export</Button>
            <Button onClick={() => navigate(-1)} variant="outline"><ArrowLeft className="h-4 w-4 mr-2" />Back</Button>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.1 }}>
          <Card>
            <CardContent className="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="space-y-2">
                <div className="text-sm text-gray-400">Confidence Score</div>
                <ConfidenceBadge score={domainData.confidence} />
              </div>
              <div className="space-y-2">
                <div className="text-sm text-gray-400">Illegal Rate</div>
                <div className="flex items-center space-x-2">
                  <div className="w-full bg-gray-700 rounded-full h-2"><div className="bg-gradient-to-r from-yellow-500 to-red-500 h-2 rounded-full" style={{ width: `${judgment.illegal_rate}%` }} /></div>
                  <span className="font-medium">{judgment.illegal_rate}%</span>
                </div>
              </div>
              <div className="space-y-2">
                <div className="text-sm text-gray-400">Status</div>
                <div className={`flex items-center space-x-2 font-medium ${judgment.status === 'Safe' ? 'text-green-400' : 'text-red-400'}`}>
                  {judgment.status === 'Safe' ? <ShieldCheck className="h-5 w-5" /> : <AlertOctagon className="h-5 w-5" />}
                  <span>{judgment.status}</span>
                </div>
              </div>
              <div className="space-y-2">
                <div className="text-sm text-gray-400">Domain/IP</div>
                <p className="font-medium font-mono">{judgment.domain_ip}</p>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.2 }} className="lg:col-span-2 space-y-8">
            <Card>
              <CardHeader><CardTitle className="flex items-center"><Server className="h-5 w-5 mr-2 text-purple-400"/>Server & Weaknesses</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div><span className="font-semibold">Server Version:</span> <span className="font-mono text-gray-300">{judgment.server_version}</span></div>
                <div>
                  <p className="font-semibold mb-2">Detected Weaknesses:</p>
                  <div className="flex flex-wrap gap-2">
                    {judgment.weaknesses.length > 0 ? judgment.weaknesses.map(w => (
                      <span key={w} className="flex items-center text-sm bg-yellow-600/20 text-yellow-300 px-3 py-1 rounded-full"><Bug className="h-4 w-4 mr-2"/>{w}</span>
                    )) : <span className="text-sm text-gray-400">None detected.</span>}
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="flex items-center"><Code className="h-5 w-5 mr-2 text-purple-400"/>Content Analysis</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div><span className="font-semibold">Category:</span> <span className="font-medium text-purple-300">{domainData.kategori}</span></div>
                <div>
                  <p className="font-semibold mb-2">Suspicious Scripts:</p>
                  <div className="space-y-2">
                    {judgment.suspicious_scripts.length > 0 ? judgment.suspicious_scripts.map(s => (
                      <div key={s} className="font-mono text-sm glass-effect p-2 rounded border border-white/10">{s}</div>
                    )) : <span className="text-sm text-gray-400">None detected.</span>}
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.3 }}>
            <Card>
              <CardHeader><CardTitle className="flex items-center"><DoorOpen className="h-5 w-5 mr-2 text-purple-400"/>Detection Summary</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="font-semibold mb-2">Shadowdoor/Defacement:</p>
                  <p className={`font-medium ${judgment.defacement_detected ? 'text-red-400' : 'text-green-400'}`}>{judgment.defacement_detected ? 'Detected' : 'Not Detected'}</p>
                </div>
                <div className="border-t border-white/10 pt-4">
                  <button onClick={() => setRecommendationsOpen(!isRecommendationsOpen)} className="w-full flex justify-between items-center font-semibold text-left">
                    Recommendations
                    {isRecommendationsOpen ? <ChevronUp /> : <ChevronDown />}
                  </button>
                  {isRecommendationsOpen && (
                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="mt-3 text-sm text-gray-300 space-y-2">
                      {judgment.recommendations.map((rec, i) => <p key={i}>- {rec}</p>)}
                    </motion.div>
                  )}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>

        <ExportModal isOpen={isExportModalOpen} onClose={() => setIsExportModalOpen(false)} data={mockCrawlData} selectedDomain={domainData} />
      </div>
    </>
  );
};

export default Analysis;