import React from 'react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Wifi, WifiOff, Server, Info, GitBranch } from 'lucide-react';
import { useApi } from '@/hooks/useApi';

const ApiInfo = () => {
  const { apiStatus, apiVersion, apiEndpoint } = useApi();
  const isConnected = apiStatus === 'Connected';

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" className="flex items-center space-x-2">
          <span>API Info</span>
          {isConnected ? (
            <Wifi className="h-4 w-4 text-green-400" />
          ) : (
            <WifiOff className="h-4 w-4 text-red-400" />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-56 glass-effect border-white/20">
        <DropdownMenuLabel>API Information</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem>
          <Server className="mr-2 h-4 w-4" />
          <span>{apiEndpoint}</span>
        </DropdownMenuItem>
        <DropdownMenuItem>
          <GitBranch className="mr-2 h-4 w-4" />
          <span>Version: {apiVersion}</span>
        </DropdownMenuItem>
        <DropdownMenuItem className={isConnected ? 'text-green-400' : 'text-red-400'}>
          {isConnected ? (
            <Wifi className="mr-2 h-4 w-4" />
          ) : (
            <WifiOff className="mr-2 h-4 w-4" />
          )}
          <span>Status: {apiStatus}</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

export default ApiInfo;