"""CAKRA - Network Mapper Agent

Maps connections between illegal websites and operators using graph analysis.
"""

from typing import Dict, List, Any, Optional
import asyncio
import logging
from datetime import datetime
import networkx as nx
import whois
import dns.resolver
from urllib.parse import urlparse

from .base import Agent

from ..core.config import MapperConfig

class NetworkMapper(Agent):
    """Maps connections between websites, operators, and infrastructure"""
    
    def __init__(self, config: MapperConfig):
        super().__init__(config)
        self.graph = nx.DiGraph()
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = config.dns_timeout
        self.whois_timeout = config.whois_timeout
        
        # Initialize empty clusters
        self.known_clusters = {}
    
    async def initialize(self) -> None:
        """Initialize network analysis resources"""
        try:
            # Test DNS resolver
            self.dns_resolver.resolve("google.com", "A")
            self.is_initialized = True
        except Exception as e:
            logging.error(f"Network mapper initialization error: {str(e)}")
            raise
    
    async def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze website network connections"""
        url = data.get("url")
        if not url:
            return {"error": "No URL provided"}
        
        try:
            # Extract domain
            domain = urlparse(url).netloc
            
            # Gather infrastructure info concurrently
            dns_info, whois_info = await asyncio.gather(
                self._get_dns_info(domain),
                self._get_whois_info(domain)
            )
            
            # Extract linked domains
            linked_domains = await self._extract_linked_domains(
                data.get("internal_links", []),
                data.get("external_links", [])
            )
            
            # Map infrastructure connections
            infra_connections = self._map_infrastructure(
                domain, dns_info, whois_info, linked_domains
            )
            
            # Identify potential clusters
            clusters = self._identify_clusters(domain, infra_connections)
            
            return {
                "domain": domain,
                "dns_info": dns_info,
                "whois_info": whois_info,
                "linked_domains": linked_domains,
                "infrastructure_connections": infra_connections,
                "clusters": clusters,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Network analysis error for {url}: {str(e)}")
            return {
                "url": url,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _get_dns_info(self, domain: str) -> Dict[str, Any]:
        """Get DNS information for domain"""
        dns_info = {
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": []
        }
        
        try:
            # A records
            answers = self.dns_resolver.resolve(domain, "A")
            dns_info["a_records"] = [str(rdata) for rdata in answers]
            
            # MX records
            try:
                answers = self.dns_resolver.resolve(domain, "MX")
                dns_info["mx_records"] = [
                    {"preference": rdata.preference, "exchange": str(rdata.exchange)}
                    for rdata in answers
                ]
            except dns.resolver.NoAnswer:
                pass
            
            # NS records
            try:
                answers = self.dns_resolver.resolve(domain, "NS")
                dns_info["ns_records"] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
            
            # TXT records
            try:
                answers = self.dns_resolver.resolve(domain, "TXT")
                dns_info["txt_records"] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
                
        except Exception as e:
            dns_info["error"] = str(e)
        
        return dns_info
    
    async def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain, timeout=self.whois_timeout)
            return {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "updated_date": w.updated_date,
                "name_servers": w.name_servers,
                "emails": w.emails
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def _extract_linked_domains(
        self,
        internal_links: List[Dict[str, str]],
        external_links: List[Dict[str, str]]
    ) -> Dict[str, List[str]]:
        """Extract and categorize linked domains"""
        internal_domains = set()
        external_domains = set()
        
        for link in internal_links:
            try:
                domain = urlparse(link["href"]).netloc
                if domain:
                    internal_domains.add(domain)
            except Exception:
                continue
        
        for link in external_links:
            try:
                domain = urlparse(link["href"]).netloc
                if domain:
                    external_domains.add(domain)
            except Exception:
                continue
        
        return {
            "internal_domains": list(internal_domains),
            "external_domains": list(external_domains)
        }
    
    def _map_infrastructure(
        self,
        domain: str,
        dns_info: Dict[str, Any],
        whois_info: Dict[str, Any],
        linked_domains: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Map infrastructure connections"""
        # Add nodes to graph
        self.graph.add_node(domain, type="domain")
        
        connections = {
            "shared_ip_addresses": [],
            "shared_nameservers": [],
            "shared_registrar": [],
            "domain_links": []
        }
        
        # Add IP addresses
        for ip in dns_info.get("a_records", []):
            self.graph.add_node(ip, type="ip_address")
            self.graph.add_edge(domain, ip, type="resolves_to")
            connections["shared_ip_addresses"].append(ip)
        
        # Add nameservers
        for ns in dns_info.get("ns_records", []):
            self.graph.add_node(ns, type="nameserver")
            self.graph.add_edge(domain, ns, type="uses_nameserver")
            connections["shared_nameservers"].append(ns)
        
        # Add registrar
        registrar = whois_info.get("registrar")
        if registrar:
            self.graph.add_node(registrar, type="registrar")
            self.graph.add_edge(domain, registrar, type="registered_by")
            connections["shared_registrar"].append(registrar)
        
        # Add domain links
        for linked_domain in linked_domains["internal_domains"]:
            self.graph.add_node(linked_domain, type="domain")
            self.graph.add_edge(domain, linked_domain, type="internal_link")
            connections["domain_links"].append({
                "domain": linked_domain,
                "type": "internal"
            })
        
        for linked_domain in linked_domains["external_domains"]:
            self.graph.add_node(linked_domain, type="domain")
            self.graph.add_edge(domain, linked_domain, type="external_link")
            connections["domain_links"].append({
                "domain": linked_domain,
                "type": "external"
            })
        
        return connections
    
    def _identify_clusters(
        self,
        domain: str,
        connections: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Identify potential operator clusters"""
        clusters = []
        
        # Find connected components in the subgraph around this domain
        subgraph = nx.ego_graph(self.graph, domain, radius=2)
        
        # Extract clusters based on different relationship types
        
        # IP-based clusters
        ip_neighbors = [
            n for n in subgraph.neighbors(domain)
            if subgraph.nodes[n]["type"] == "ip_address"
        ]
        for ip in ip_neighbors:
            # Find other domains using this IP
            ip_domains = [
                n for n in subgraph.neighbors(ip)
                if subgraph.nodes[n]["type"] == "domain" and n != domain
            ]
            if ip_domains:
                clusters.append({
                    "type": "shared_infrastructure",
                    "indicator": f"Shared IP: {ip}",
                    "domains": ip_domains,
                    "confidence": 0.8
                })
        
        # Registrar-based clusters
        registrar_neighbors = [
            n for n in subgraph.neighbors(domain)
            if subgraph.nodes[n]["type"] == "registrar"
        ]
        for registrar in registrar_neighbors:
            registrar_domains = [
                n for n in subgraph.neighbors(registrar)
                if subgraph.nodes[n]["type"] == "domain" and n != domain
            ]
            if registrar_domains:
                clusters.append({
                    "type": "shared_registrar",
                    "indicator": f"Shared Registrar: {registrar}",
                    "domains": registrar_domains,
                    "confidence": 0.4
                })
        
        # Link-based clusters
        for connection in connections["domain_links"]:
            if connection["type"] == "internal":
                clusters.append({
                    "type": "direct_link",
                    "indicator": "Internal Link",
                    "domains": [connection["domain"]],
                    "confidence": 0.9
                })
        
        return clusters
    
    async def cleanup(self) -> None:
        """Clean up resources"""
        self.graph.clear()
        self.is_initialized = False