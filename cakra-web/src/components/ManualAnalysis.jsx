import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { ScanLine, Loader2, ShieldCheck, AlertOctagon } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';
import { api } from '@/lib/api';
import { transformScanResult } from '@/utils/dataTransformers';

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
  const [baseDomain, setBaseDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [scanDomains, setScanDomains] = useState({
    id: false,
    coId: false,
    com: false,
    net: false,
    org: false,
    info: false,
    biz: false,
    online: false,
    site: false,
    store: false,
    xyz: false
  });
  const { toast } = useToast();

  const handleAnalyze = async () => {
    // Check if any domain scanning is selected
    const selectedDomains = Object.entries(scanDomains).filter(([_, selected]) => selected);
    
    if (!url && !baseDomain && selectedDomains.length === 0) {
      toast({
        title: "Input Required",
        description: "Please enter a URL, base domain, or select domain extensions to scan.",
        variant: "destructive",
      });
      return;
    }

    // If URL is provided, validate it
    if (url) {
      try {
        new URL(url);
      } catch {
        toast({
          title: "Invalid URL",
          description: "Please enter a valid URL (e.g., https://example.com).",
          variant: "destructive",
        });
        return;
      }
    }

    // If base domain is provided, validate it (basic check)
    if (baseDomain && !/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/.test(baseDomain)) {
      toast({
        title: "Invalid Base Domain",
        description: "Please enter a valid domain name (e.g., example).",
        variant: "destructive",
      });
      return;
    }

    setIsLoading(true);
    setResult(null);

    try {
      // Determine the base domain to use
      let domainToUse = '';
      if (url) {
        domainToUse = new URL(url).hostname.replace(/^www\./, '');
      } else if (baseDomain) {
        domainToUse = baseDomain;
      }

      if (selectedDomains.length > 0 && domainToUse) {
        // Domain scanning - scan selected domain extensions
        // Map checkbox keys to actual domain extensions
        const domainMap = {
          id: '.id',
          coId: '.co.id',
          com: '.com',
          net: '.net',
          org: '.org',
          info: '.info',
          biz: '.biz',
          online: '.online',
          site: '.site',
          store: '.store',
          xyz: '.xyz'
        };
        
        const urlsToScan = [];
        
        // Add the domain with selected extensions
        selectedDomains.forEach(([key]) => {
          const ext = domainMap[key];
          urlsToScan.push(`https://${domainToUse}${ext}`);
          urlsToScan.push(`https://www.${domainToUse}${ext}`);
        });
        
        // Also scan common subdomains for selected extensions
        const subdomains = ['mail', 'ftp', 'admin', 'blog', 'shop', 'api'];
        selectedDomains.forEach(([key]) => {
          const ext = domainMap[key];
          subdomains.forEach(sub => {
            urlsToScan.push(`https://${sub}.${domainToUse}${ext}`);
          });
        });

        toast({
          title: "Domain Scanning Started",
          description: `Scanning ${urlsToScan.length} domain variations for "${domainToUse}"...`,
        });

        // Scan all URLs (limit to first 20 for performance)
        const scanPromises = urlsToScan.slice(0, 20).map(async (scanUrl) => {
          try {
            return await api.scanUrl(scanUrl);
          } catch (error) {
            console.warn(`Failed to scan ${scanUrl}:`, error);
            return null;
          }
        });

        const results = await Promise.all(scanPromises);
        const validResults = results.filter(r => r !== null);

        if (validResults.length > 0) {
          // Show summary of domain scan
          const highRisk = validResults.filter(r => r.content_analysis?.illegal_rate > 70).length;
          const mediumRisk = validResults.filter(r => r.content_analysis?.illegal_rate > 30 && r.content_analysis?.illegal_rate <= 70).length;
          
          toast({
            title: "Domain Scan Complete",
            description: `Scanned ${validResults.length} domains. High risk: ${highRisk}, Medium risk: ${mediumRisk}`,
          });
          
          // Show result for the first valid result
          const displayResult = validResults[0];
          if (displayResult) {
            const transformed = transformScanResult(displayResult);
            setResult({
              status: transformed.structured_judgment.status,
              confidence: transformed.confidence
            });
          }
        } else {
          throw new Error("No domains could be scanned successfully");
        }
      } else if (url) {
        // Single URL scanning
        const apiResult = await api.scanUrl(url);
        const transformed = transformScanResult(apiResult);

        setResult({
          status: transformed.structured_judgment.status,
          confidence: transformed.confidence
        });

        toast({
          title: "Analysis Complete",
          description: `URL ${url} has been analyzed successfully.`,
        });
      } else {
        throw new Error("Please provide a URL or select domain extensions to scan");
      }
    } catch (error) {
      console.error('Analysis error:', error);
      toast({
        title: "Analysis Failed",
        description: error.message || "Failed to analyze. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
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
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              URL to Analyze (Optional)
            </label>
            <Input
              placeholder="Enter full URL (e.g., https://example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleAnalyze()}
              disabled={isLoading}
            />
          </div>
          
          <div className="text-center text-gray-400 text-sm">OR</div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Base Domain Name (Optional)
            </label>
            <Input
              placeholder="Enter domain name without extension (e.g., tokopedia)"
              value={baseDomain}
              onChange={(e) => setBaseDomain(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleAnalyze()}
              disabled={isLoading}
            />
          </div>
        </div>

        <div className="flex items-center space-x-2">
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
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-gray-300">Scan Domain Extensions:</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries({
              id: '.id',
              coId: '.co.id', 
              com: '.com',
              net: '.net',
              org: '.org',
              info: '.info',
              biz: '.biz',
              online: '.online',
              site: '.site',
              store: '.store',
              xyz: '.xyz'
            }).map(([key, label]) => (
              <div key={key} className="flex items-center space-x-2">
                <Checkbox
                  id={`domain-${key}`}
                  checked={scanDomains[key]}
                  onCheckedChange={(checked) => 
                    setScanDomains(prev => ({ ...prev, [key]: checked }))
                  }
                  disabled={isLoading}
                />
                <label
                  htmlFor={`domain-${key}`}
                  className="text-sm text-gray-300 cursor-pointer"
                >
                  {label}
                </label>
              </div>
            ))}
          </div>
          <p className="text-xs text-gray-400">
            Select domain extensions to scan. If using base domain, these will be combined (e.g., "tokopedia" + ".id" = "tokopedia.id").
            If using URL, the domain will be extracted and scanned with selected extensions.
          </p>
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