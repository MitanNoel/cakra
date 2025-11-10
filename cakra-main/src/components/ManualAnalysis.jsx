import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { ScanLine, Loader2, ShieldCheck, AlertOctagon } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';

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

const ManualAnalysis = () => {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const { toast } = useToast();

  const mockAnalyzeUrl = (urlToAnalyze) => {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (!urlToAnalyze || !urlToAnalyze.includes('.')) {
          resolve(null);
          return;
        }
        
        const isMalicious = Math.random() > 0.3;
        const confidence = Math.random();
        
        resolve({
          status: isMalicious ? 'Malicious' : 'Safe',
          confidence: confidence,
        });
      }, 1500);
    });
  };

  const handleAnalyze = async () => {
    if (!url) {
      toast({
        title: "URL is required",
        description: "Please enter a URL to analyze.",
        variant: "destructive",
      });
      return;
    }
    setIsLoading(true);
    setResult(null);
    const analysisResult = await mockAnalyzeUrl(url);
    setIsLoading(false);
    setResult(analysisResult);
    if (analysisResult) {
      toast({
        title: "Analysis Complete",
        description: `URL ${url} has been analyzed.`,
      });
    } else {
       toast({
        title: "Invalid URL",
        description: "Please enter a valid URL.",
        variant: "destructive",
      });
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <ScanLine className="h-5 w-5 text-purple-400" />
          <span>Manual URL Analysis</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center space-x-2">
          <Input
            placeholder="Enter URL to analyze (e.g., example.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAnalyze()}
            disabled={isLoading}
          />
          <Button
            onClick={handleAnalyze}
            disabled={isLoading}
            className="galaxy-gradient-button hover:galaxy-gradient-button"
          >
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              'Analyze'
            )}
          </Button>
        </div>
        <AnimatePresence>
          {result && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.4 }}
            >
              <div className="glass-effect p-4 rounded-lg border border-white/10 mt-4 flex items-center justify-between">
                <h4 className="font-semibold text-white">Structured Judgment:</h4>
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    <span className="text-sm text-gray-300">Confidence:</span>
                    <ConfidenceBadge score={result.confidence} />
                  </div>
                  <div className={`flex items-center space-x-2 font-medium ${result.status === 'Safe' ? 'text-green-400' : 'text-red-400'}`}>
                    {result.status === 'Safe' ? <ShieldCheck className="h-5 w-5" /> : <AlertOctagon className="h-5 w-5" />}
                    <span>{result.status}</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </CardContent>
    </Card>
  );
};

export default ManualAnalysis;