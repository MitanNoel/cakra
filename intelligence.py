import whois
import dns.resolver
import dns.reversename
import socket
import requests
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import logging
from urllib.parse import urlparse
import re

class IntelligenceGatherer:
    """Enhanced intelligence gathering for domains and websites."""
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10
    
    def get_domain_from_url(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove www. prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except Exception:
            return url.replace('https://', '').replace('http://', '').split('/')[0].lower()
    
    def get_whois_data(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS data for a domain with timeout handling."""
        try:
            # Clean domain name
            domain = domain.replace('www.', '').split('/')[0]
            
            # Set shorter timeout for WHOIS lookups
            import socket
            socket.setdefaulttimeout(10)  # 10 second timeout
            
            # Use the correct function name for newer whois package
            import whois as whois_module
            w = whois_module.whois(domain)
            
            # Extract key information
            whois_data = {
                'domain_name': getattr(w, 'domain_name', None),
                'registrar': getattr(w, 'registrar', None),
                'creation_date': self._format_date(getattr(w, 'creation_date', None)),
                'expiration_date': self._format_date(getattr(w, 'expiration_date', None)),
                'updated_date': self._format_date(getattr(w, 'updated_date', None)),
                'name_servers': getattr(w, 'name_servers', None),
                'status': getattr(w, 'status', None),
                'emails': getattr(w, 'emails', None),
                'country': getattr(w, 'country', None),
                'org': getattr(w, 'org', None),
                'registrant_name': getattr(w, 'name', None),
                'registrant_postal_code': getattr(w, 'registrant_postal_code', None),
            }
            
            # Calculate domain age
            if whois_data['creation_date']:
                try:
                    if isinstance(whois_data['creation_date'], list):
                        creation_date = whois_data['creation_date'][0]
                    else:
                        creation_date = whois_data['creation_date']
                    
                    if isinstance(creation_date, str):
                        # Try to parse string date
                        creation_date = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                    
                    now = datetime.now(timezone.utc)
                    if creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
                    
                    age_days = (now - creation_date).days
                    whois_data['domain_age_days'] = age_days
                    whois_data['is_newly_registered'] = age_days < 30  # Less than 30 days
                    whois_data['is_very_new'] = age_days < 7  # Less than 7 days
                except Exception as e:
                    logging.warning(f"Error calculating domain age: {e}")
                    whois_data['domain_age_days'] = None
                    whois_data['is_newly_registered'] = False
                    whois_data['is_very_new'] = False
            
            return {
                'success': True,
                'data': whois_data,
                'suspicious_indicators': self._analyze_whois_suspicion(whois_data)
            }
            
        except socket.timeout:
            logging.warning(f"WHOIS lookup timed out for {domain}")
            return {
                'success': False,
                'error': 'WHOIS lookup timed out',
                'data': {},
                'suspicious_indicators': ['WHOIS lookup timed out - could not verify domain information']
            }
        except Exception as e:
            logging.error(f"WHOIS lookup failed for {domain}: {e}")
            return {
                'success': False,
                'error': str(e),
                'data': {},
                'suspicious_indicators': []
            }
        finally:
            # Reset socket timeout to default
            socket.setdefaulttimeout(None)
    
    def _format_date(self, date_obj):
        """Format date object to string."""
        if not date_obj:
            return None
        
        if isinstance(date_obj, list):
            date_obj = date_obj[0]
        
        if isinstance(date_obj, datetime):
            return date_obj.isoformat()
        
        return str(date_obj)
    
    def _analyze_whois_suspicion(self, whois_data: Dict) -> List[str]:
        """Analyze WHOIS data for suspicious indicators."""
        indicators = []
        
        # Check domain age
        if whois_data.get('is_very_new'):
            indicators.append("Domain registered less than 7 days ago (very suspicious)")
        elif whois_data.get('is_newly_registered'):
            indicators.append("Domain registered less than 30 days ago (suspicious)")
        
        # Check for privacy protection (not necessarily suspicious, but worth noting)
        registrar = str(whois_data.get('registrar', '')).lower()
        if 'privacy' in registrar or 'whoisguard' in registrar or 'domains by proxy' in registrar:
            indicators.append("Domain uses privacy protection service")
        
        # Check for suspicious registrars (common with malicious domains)
        suspicious_registrars = [
            'namecheap', 'godaddy', 'dynadot', 'porkbun',  # Not inherently suspicious, but popular with bad actors
            'freenom', 'dot.tk'  # Free domain providers, often abused
        ]
        
        if any(susp in registrar for susp in suspicious_registrars[-2:]):  # Only flag free providers
            indicators.append(f"Domain registered with provider often used by malicious actors: {registrar}")
        
        # Check for missing key information
        if not whois_data.get('registrant_name') and not whois_data.get('org'):
            indicators.append("Missing registrant information")
        
        # Check expiration date (domains expiring soon might be abandoned)
        if whois_data.get('expiration_date'):
            try:
                exp_date = whois_data['expiration_date']
                if isinstance(exp_date, str):
                    exp_date = datetime.fromisoformat(exp_date.replace('Z', '+00:00'))
                
                now = datetime.now(timezone.utc)
                if exp_date.tzinfo is None:
                    exp_date = exp_date.replace(tzinfo=timezone.utc)
                
                days_to_expiry = (exp_date - now).days
                if days_to_expiry < 30:
                    indicators.append(f"Domain expires in {days_to_expiry} days (potentially abandoned)")
            except Exception:
                pass
        
        return indicators
    
    def get_dns_analysis(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS analysis."""
        try:
            # Clean domain name
            domain = domain.replace('www.', '').split('/')[0]
            
            dns_data = {
                'a_records': [],
                'aaaa_records': [],
                'mx_records': [],
                'ns_records': [],
                'txt_records': [],
                'cname_records': [],
                'soa_record': None,
                'ptr_records': []
            }
            
            # Get A records (IPv4)
            try:
                answers = self.dns_resolver.resolve(domain, 'A')
                dns_data['a_records'] = [str(rdata) for rdata in answers]
            except Exception as e:
                logging.debug(f"A record lookup failed: {e}")
            
            # Get AAAA records (IPv6)
            try:
                answers = self.dns_resolver.resolve(domain, 'AAAA')
                dns_data['aaaa_records'] = [str(rdata) for rdata in answers]
            except Exception as e:
                logging.debug(f"AAAA record lookup failed: {e}")
            
            # Get MX records
            try:
                answers = self.dns_resolver.resolve(domain, 'MX')
                dns_data['mx_records'] = [{'priority': rdata.preference, 'exchange': str(rdata.exchange)} 
                                        for rdata in answers]
            except Exception as e:
                logging.debug(f"MX record lookup failed: {e}")
            
            # Get NS records
            try:
                answers = self.dns_resolver.resolve(domain, 'NS')
                dns_data['ns_records'] = [str(rdata) for rdata in answers]
            except Exception as e:
                logging.debug(f"NS record lookup failed: {e}")
            
            # Get TXT records
            try:
                answers = self.dns_resolver.resolve(domain, 'TXT')
                dns_data['txt_records'] = [str(rdata) for rdata in answers]
            except Exception as e:
                logging.debug(f"TXT record lookup failed: {e}")
            
            # Get SOA record
            try:
                answers = self.dns_resolver.resolve(domain, 'SOA')
                if answers:
                    soa = answers[0]
                    dns_data['soa_record'] = {
                        'mname': str(soa.mname),
                        'rname': str(soa.rname),
                        'serial': soa.serial,
                        'refresh': soa.refresh,
                        'retry': soa.retry,
                        'expire': soa.expire,
                        'minimum': soa.minimum
                    }
            except Exception as e:
                logging.debug(f"SOA record lookup failed: {e}")
            
            # Reverse DNS lookup for A records
            for ip in dns_data['a_records']:
                try:
                    addr = dns.reversename.from_address(ip)
                    answers = self.dns_resolver.resolve(addr, 'PTR')
                    dns_data['ptr_records'].append({
                        'ip': ip,
                        'hostname': [str(rdata) for rdata in answers]
                    })
                except Exception as e:
                    logging.debug(f"PTR record lookup failed for {ip}: {e}")
            
            return {
                'success': True,
                'data': dns_data,
                'suspicious_indicators': self._analyze_dns_suspicion(dns_data, domain)
            }
            
        except Exception as e:
            logging.error(f"DNS analysis failed for {domain}: {e}")
            return {
                'success': False,
                'error': str(e),
                'data': {},
                'suspicious_indicators': []
            }
    
    def _analyze_dns_suspicion(self, dns_data: Dict, domain: str) -> List[str]:
        """Analyze DNS data for suspicious indicators."""
        indicators = []
        
        # Check for suspicious hosting providers
        suspicious_hosting = [
            'cloudflare',  # Not suspicious, but often used by malicious sites for protection
            'namecheap', 'hostinger', 'shinjiru',  # Cheap hosting often used by bad actors
            'bulletproof'  # Known bulletproof hosting
        ]
        
        # Check PTR records for suspicious hosting
        for ptr_record in dns_data.get('ptr_records', []):
            hostnames = ptr_record.get('hostname', [])
            for hostname in hostnames:
                hostname_lower = hostname.lower()
                for suspicious in suspicious_hosting[1:]:  # Skip cloudflare
                    if suspicious in hostname_lower:
                        indicators.append(f"Hosted on potentially suspicious provider: {hostname}")
        
        # Check for multiple A records (could indicate load balancing or CDN, but also suspicious)
        a_records = dns_data.get('a_records', [])
        if len(a_records) > 5:
            indicators.append(f"Large number of A records ({len(a_records)}) - possible CDN or suspicious")
        
        # Check for suspicious TXT records
        txt_records = dns_data.get('txt_records', [])
        for txt in txt_records:
            txt_lower = txt.lower()
            if any(suspicious in txt_lower for suspicious in ['bitcoin', 'crypto', 'gambling', 'casino']):
                indicators.append(f"Suspicious TXT record content: {txt[:100]}...")
        
        # Check for missing MX records (suspicious for legitimate businesses)
        if not dns_data.get('mx_records') and not any('mail' in domain.lower() for word in ['mail', 'email', 'smtp']):
            indicators.append("No MX records found (no email capability)")
        
        # Check for suspicious nameservers
        ns_records = dns_data.get('ns_records', [])
        suspicious_ns = ['freenom', 'afraid.org', 'dynamic', 'dyndns']
        for ns in ns_records:
            ns_lower = ns.lower()
            for suspicious in suspicious_ns:
                if suspicious in ns_lower:
                    indicators.append(f"Suspicious nameserver: {ns}")
        
        # Check for short TTL (could indicate frequent IP changes)
        # Note: This would require additional DNS queries with TTL checking
        
        return indicators
    
    def get_geolocation_info(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for an IP address."""
        try:
            # Using a free IP geolocation service
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'timezone': data.get('timezone'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'suspicious_indicators': self._analyze_geo_suspicion(data)
                    }
            
            return {'success': False, 'error': 'Geolocation lookup failed'}
            
        except Exception as e:
            logging.error(f"Geolocation lookup failed for {ip}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_geo_suspicion(self, geo_data: Dict) -> List[str]:
        """Analyze geolocation data for suspicious indicators."""
        indicators = []
        
        # Check for countries commonly associated with cybercrime
        suspicious_countries = ['CN', 'RU', 'KP', 'IR']  # China, Russia, North Korea, Iran
        high_risk_countries = ['UA', 'BD', 'PK', 'NG']  # Ukraine, Bangladesh, Pakistan, Nigeria
        
        country_code = geo_data.get('countryCode', '')
        if country_code in suspicious_countries:
            indicators.append(f"Hosted in high-risk country: {geo_data.get('country')}")
        elif country_code in high_risk_countries:
            indicators.append(f"Hosted in elevated-risk country: {geo_data.get('country')}")
        
        # Check for suspicious ISPs/Organizations
        isp = geo_data.get('isp', '').lower()
        org = geo_data.get('org', '').lower()
        
        suspicious_isps = ['bulletproof', 'offshore', 'privacy', 'anonymous', 'vpn', 'proxy']
        for suspicious in suspicious_isps:
            if suspicious in isp or suspicious in org:
                indicators.append(f"Suspicious hosting provider: {geo_data.get('isp')}")
                break
        
        return indicators
    
    def comprehensive_domain_analysis(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive analysis of a domain."""
        domain = self.get_domain_from_url(url)
        
        analysis = {
            'domain': domain,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'whois': {},
            'dns': {},
            'geolocation': {},
            'wayback': {},
            'overall_risk_score': 0,
            'risk_factors': [],
            'recommendations': []
        }
        
        # WHOIS Analysis
        logging.info(f"Performing WHOIS lookup for {domain}")
        whois_result = self.get_whois_data(domain)
        analysis['whois'] = whois_result
        if whois_result.get('suspicious_indicators'):
            analysis['risk_factors'].extend(whois_result['suspicious_indicators'])
        
        # DNS Analysis
        logging.info(f"Performing DNS analysis for {domain}")
        dns_result = self.get_dns_analysis(domain)
        analysis['dns'] = dns_result
        if dns_result.get('suspicious_indicators'):
            analysis['risk_factors'].extend(dns_result['suspicious_indicators'])
        
        # Geolocation Analysis (for first A record)
        if dns_result.get('success') and dns_result['data'].get('a_records'):
            first_ip = dns_result['data']['a_records'][0]
            logging.info(f"Performing geolocation lookup for {first_ip}")
            geo_result = self.get_geolocation_info(first_ip)
            analysis['geolocation'] = geo_result
            if geo_result.get('suspicious_indicators'):
                analysis['risk_factors'].extend(geo_result['suspicious_indicators'])
        
        # Wayback Machine Analysis
        logging.info(f"Performing Wayback Machine lookup for {domain}")
        wayback_result = self.get_wayback_machine_data(domain)
        analysis['wayback'] = wayback_result
        if wayback_result.get('suspicious_indicators'):
            analysis['risk_factors'].extend(wayback_result['suspicious_indicators'])
        
        # Calculate overall risk score
        analysis['overall_risk_score'] = self._calculate_risk_score(analysis)
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _calculate_risk_score(self, analysis: Dict) -> int:
        """Calculate overall risk score (0-100)."""
        score = 0
        
        # WHOIS-based scoring
        whois_data = analysis.get('whois', {}).get('data', {})
        if whois_data.get('is_very_new'):
            score += 40
        elif whois_data.get('is_newly_registered'):
            score += 25
        
        # DNS-based scoring
        dns_data = analysis.get('dns', {}).get('data', {})
        if not dns_data.get('mx_records'):
            score += 10
        
        # Wayback Machine-based scoring
        wayback_data = analysis.get('wayback', {})
        if wayback_data.get('success'):
            wayback_age = wayback_data.get('wayback_age_days', 0)
            if wayback_age < 30:
                score += 35
            elif wayback_age < 365:
                score += 20
            
            total_captures = wayback_data.get('total_captures', 0)
            if total_captures < 5:
                score += 15
        
        # Risk factor scoring
        risk_factors = analysis.get('risk_factors', [])
        score += min(len(risk_factors) * 5, 30)  # Max 30 points for risk factors
        
        # Geographic scoring
        geo_data = analysis.get('geolocation', {})
        if 'high-risk country' in str(geo_data.get('suspicious_indicators', [])):
            score += 20
        elif 'elevated-risk country' in str(geo_data.get('suspicious_indicators', [])):
            score += 10
        
        return min(score, 100)  # Cap at 100
    
    def get_wayback_machine_data(self, domain: str) -> Dict[str, Any]:
        """Get historical data from Wayback Machine."""
        try:
            # Wayback Machine CDX API
            cdx_url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=timestamp,original,statuscode,length&limit=100"
            
            response = requests.get(cdx_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if len(data) <= 1:  # Only header row
                    return {
                        'success': True,
                        'total_captures': 0,
                        'first_capture': None,
                        'last_capture': None,
                        'captures': [],
                        'suspicious_indicators': ['No historical data found in Wayback Machine']
                    }
                
                # Remove header row
                captures = data[1:] if len(data) > 1 else []
                
                # Parse timestamps
                timestamps = []
                for capture in captures:
                    if len(capture) >= 1:
                        try:
                            # Wayback timestamp format: YYYYMMDDHHMMSS
                            ts_str = capture[0]
                            if len(ts_str) >= 8:
                                year = int(ts_str[:4])
                                month = int(ts_str[4:6])
                                day = int(ts_str[6:8])
                                timestamps.append(datetime(year, month, day))
                        except (ValueError, IndexError):
                            continue
                
                if timestamps:
                    first_capture = min(timestamps)
                    last_capture = max(timestamps)
                    
                    # Calculate domain age from first capture
                    now = datetime.now()
                    wayback_age_days = (now - first_capture).days
                    
                    # Analyze capture patterns
                    suspicious_indicators = self._analyze_wayback_suspicion(captures, wayback_age_days)
                    
                    return {
                        'success': True,
                        'total_captures': len(captures),
                        'first_capture': first_capture.isoformat(),
                        'last_capture': last_capture.isoformat(),
                        'wayback_age_days': wayback_age_days,
                        'captures': captures[:10],  # Return first 10 captures
                        'suspicious_indicators': suspicious_indicators
                    }
                else:
                    return {
                        'success': True,
                        'total_captures': 0,
                        'first_capture': None,
                        'last_capture': None,
                        'captures': [],
                        'suspicious_indicators': ['Unable to parse capture timestamps']
                    }
            else:
                return {
                    'success': False,
                    'error': f'Wayback Machine API returned status {response.status_code}',
                    'suspicious_indicators': []
                }
                
        except Exception as e:
            logging.error(f"Wayback Machine lookup failed for {domain}: {e}")
            return {
                'success': False,
                'error': str(e),
                'suspicious_indicators': []
            }
    
    def _analyze_wayback_suspicion(self, captures: List, wayback_age_days: int) -> List[str]:
        """Analyze Wayback Machine data for suspicious indicators."""
        indicators = []
        
        # Check domain age from Wayback data
        if wayback_age_days < 30:
            indicators.append(f"Domain has very limited history ({wayback_age_days} days in Wayback Machine)")
        elif wayback_age_days < 365:
            indicators.append(f"Domain has limited history ({wayback_age_days} days in Wayback Machine)")
        
        # Check capture frequency and patterns
        if len(captures) < 5:
            indicators.append("Very few historical captures found")
        
        # Check for recent mass captures (could indicate suspicious activity)
        recent_captures = 0
        one_year_ago = datetime.now().replace(year=datetime.now().year - 1)
        
        for capture in captures:
            if len(capture) >= 1:
                try:
                    ts_str = capture[0]
                    if len(ts_str) >= 8:
                        year = int(ts_str[:4])
                        month = int(ts_str[4:6])
                        day = int(ts_str[6:8])
                        capture_date = datetime(year, month, day)
                        
                        if capture_date > one_year_ago:
                            recent_captures += 1
                except (ValueError, IndexError):
                    continue
        
        if recent_captures > 50:  # Arbitrary threshold
            indicators.append(f"High number of recent captures ({recent_captures}) - possible suspicious activity")
        
        return indicators

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        risk_score = analysis.get('overall_risk_score', 0)
        
        if risk_score >= 80:
            recommendations.append("HIGH RISK: Block this domain immediately")
            recommendations.append("Conduct thorough security investigation")
            recommendations.append("Consider adding to threat intelligence feeds")
        elif risk_score >= 60:
            recommendations.append("MEDIUM RISK: Implement additional monitoring")
            recommendations.append("Consider requiring additional authentication")
            recommendations.append("Review access logs for this domain")
        elif risk_score >= 40:
            recommendations.append("LOW RISK: Monitor periodically")
            recommendations.append("Maintain standard security controls")
        else:
            recommendations.append("MINIMAL RISK: Standard monitoring sufficient")
        
        # Specific recommendations based on findings
        whois_data = analysis.get('whois', {}).get('data', {})
        if whois_data.get('is_very_new'):
            recommendations.append("Domain is very new - exercise caution")
        
        if whois_data.get('privacy_protected'):
            recommendations.append("Domain uses privacy protection - verify legitimacy")
        
        dns_data = analysis.get('dns', {})
        if not dns_data.get('has_mx_record'):
            recommendations.append("No email configuration found - suspicious for business domains")
        
        geo_data = analysis.get('geolocation', {})
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']  # Example high-risk countries
        if geo_data.get('country_code') in high_risk_countries:
            recommendations.append("Domain hosted in high-risk geographic location")
        
        wayback_data = analysis.get('wayback', {})
        if wayback_data.get('suspicious_indicators'):
            recommendations.append("Historical analysis shows suspicious patterns")
        
        if analysis.get('risk_factors'):
            recommendations.append("Multiple risk factors identified - comprehensive review recommended")
        
        return recommendations
