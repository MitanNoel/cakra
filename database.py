import sqlite3
import json
import time
from typing import Dict, List, Optional, Any
import logging

class ScanDatabase:
    """SQLite database handler for scan results with caching and feedback system."""
    
    def __init__(self, db_file: str = "scan_results.db"):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Main scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                judgment TEXT,
                confidence INTEGER,
                illegal_rate INTEGER,
                text_result TEXT,
                vision_results TEXT,  -- JSON array
                server_info TEXT,     -- JSON object
                shadowdoor_links TEXT, -- JSON array
                vulnerabilities TEXT,  -- JSON array
                new_keywords TEXT,     -- JSON array
                error TEXT,
                cached BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Feedback table for AI learning
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                original_judgment TEXT,
                original_confidence INTEGER,
                feedback_type TEXT CHECK(feedback_type IN ('correct', 'incorrect', 'false_positive', 'false_negative', 'unsure')),
                user_comment TEXT,
                detailed_feedback TEXT,  -- JSON object for detailed feedback
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (url) REFERENCES scan_results (url)
            )
        ''')
        
        # Domain intelligence cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                whois_data TEXT,      -- JSON object
                dns_records TEXT,     -- JSON object
                registration_date TEXT,
                registrar TEXT,
                creation_days_ago INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan statistics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date DATE DEFAULT (date('now')),
                total_scanned INTEGER DEFAULT 0,
                dangerous_count INTEGER DEFAULT 0,
                potential_count INTEGER DEFAULT 0,
                safe_count INTEGER DEFAULT 0,
                error_count INTEGER DEFAULT 0
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_url ON scan_results(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_judgment ON scan_results(judgment)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_confidence ON scan_results(confidence)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON scan_results(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON domain_intelligence(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_feedback_url ON feedback(url)')
        
        conn.commit()
        conn.close()
    
    def save_scan_result(self, result: Dict[str, Any]) -> bool:
        """Save or update a scan result."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Convert lists/dicts to JSON strings
            vision_results = json.dumps(result.get('vision_results', []))
            server_info = json.dumps(result.get('server_info', {}))
            shadowdoor_links = json.dumps(result.get('shadowdoor_links', []))
            vulnerabilities = json.dumps(result.get('vulnerabilities', []))
            new_keywords = json.dumps(result.get('new_keywords', []))
            
            cursor.execute('''
                INSERT OR REPLACE INTO scan_results 
                (url, judgment, confidence, illegal_rate, text_result, vision_results, server_info, 
                 shadowdoor_links, vulnerabilities, new_keywords, error, cached, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                result['url'],
                result.get('judgment'),
                result.get('confidence'),
                result.get('illegal_rate'),
                result.get('text_result'),
                vision_results,
                server_info,
                shadowdoor_links,
                vulnerabilities,
                new_keywords,
                result.get('error'),
                result.get('cached', False)
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logging.error(f"Error saving scan result: {e}")
            return False
    
    def get_scan_result(self, url: str) -> Optional[Dict[str, Any]]:
        """Get a specific scan result by URL."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT url, judgment, confidence, illegal_rate, text_result, vision_results, server_info,
                       shadowdoor_links, vulnerabilities, new_keywords, error, cached,
                       created_at, updated_at
                FROM scan_results WHERE url = ?
            ''', (url,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'url': row[0],
                    'judgment': row[1],
                    'confidence': row[2],
                    'illegal_rate': row[3],
                    'text_result': row[4],
                    'vision_results': json.loads(row[5]) if row[5] else [],
                    'server_info': json.loads(row[6]) if row[6] else {},
                    'shadowdoor_links': json.loads(row[7]) if row[7] else [],
                    'vulnerabilities': json.loads(row[8]) if row[8] else [],
                    'new_keywords': json.loads(row[9]) if row[9] else [],
                    'error': row[10],
                    'cached': row[11],
                    'created_at': row[12],
                    'updated_at': row[13]
                }
            return None
        except Exception as e:
            logging.error(f"Error getting scan result: {e}")
            return None
    
    def get_all_scan_results(self) -> List[Dict[str, Any]]:
        """Get all scan results."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT url, judgment, confidence, illegal_rate, text_result, vision_results, server_info,
                       shadowdoor_links, vulnerabilities, new_keywords, error, cached,
                       created_at, updated_at
                FROM scan_results ORDER BY updated_at DESC
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for row in rows:
                results.append({
                    'url': row[0],
                    'judgment': row[1],
                    'confidence': row[2],
                    'illegal_rate': row[3],
                    'text_result': row[4],
                    'vision_results': json.loads(row[5]) if row[5] else [],
                    'server_info': json.loads(row[6]) if row[6] else {},
                    'shadowdoor_links': json.loads(row[7]) if row[7] else [],
                    'vulnerabilities': json.loads(row[8]) if row[8] else [],
                    'new_keywords': json.loads(row[9]) if row[9] else [],
                    'error': row[10],
                    'cached': row[11],
                    'created_at': row[12],
                    'updated_at': row[13]
                })
            return results
        except Exception as e:
            logging.error(f"Error getting all scan results: {e}")
            return []
    
    def query_results(self, confidence_min: int = None, confidence_max: int = None, 
                     judgment_contains: str = None, limit: int = None) -> List[Dict[str, Any]]:
        """Query scan results with filters."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            query = '''
                SELECT url, judgment, confidence, illegal_rate, text_result, vision_results, server_info,
                       shadowdoor_links, vulnerabilities, new_keywords, error, cached,
                       created_at, updated_at
                FROM scan_results WHERE 1=1
            '''
            params = []
            
            if confidence_min is not None:
                query += ' AND confidence >= ?'
                params.append(confidence_min)
            
            if confidence_max is not None:
                query += ' AND confidence <= ?'
                params.append(confidence_max)
            
            if judgment_contains:
                query += ' AND judgment LIKE ?'
                params.append(f'%{judgment_contains}%')
            
            query += ' ORDER BY updated_at DESC'
            
            if limit:
                query += ' LIMIT ?'
                params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for row in rows:
                results.append({
                    'url': row[0],
                    'judgment': row[1],
                    'confidence': row[2],
                    'text_result': row[3],
                    'vision_results': json.loads(row[4]) if row[4] else [],
                    'server_info': json.loads(row[5]) if row[5] else {},
                    'shadowdoor_links': json.loads(row[6]) if row[6] else [],
                    'vulnerabilities': json.loads(row[7]) if row[7] else [],
                    'new_keywords': json.loads(row[8]) if row[8] else [],
                    'error': row[9],
                    'cached': row[10],
                    'created_at': row[11],
                    'updated_at': row[12]
                })
            return results
        except Exception as e:
            logging.error(f"Error querying scan results: {e}")
            return []
    
    def save_feedback(self, url: str, feedback_type: str, user_comment: str = "", 
                     detailed_feedback: Dict[str, Any] = None) -> bool:
        """Save user feedback for AI learning."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Get the original judgment and confidence
            result = self.get_scan_result(url)
            if not result:
                return False
            
            cursor.execute('''
                INSERT INTO feedback (url, original_judgment, original_confidence, 
                                    feedback_type, user_comment, detailed_feedback)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                url,
                result.get('judgment'),
                result.get('confidence'),
                feedback_type,
                user_comment,
                json.dumps(detailed_feedback) if detailed_feedback else None
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logging.error(f"Error saving feedback: {e}")
            return False
    
    def get_feedback_stats(self) -> Dict[str, Any]:
        """Get feedback statistics for AI performance analysis."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_feedback,
                    SUM(CASE WHEN feedback_type = 'correct' THEN 1 ELSE 0 END) as correct_feedback,
                    SUM(CASE WHEN feedback_type = 'incorrect' THEN 1 ELSE 0 END) as incorrect_feedback,
                    SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as false_positive_feedback,
                    SUM(CASE WHEN feedback_type = 'false_negative' THEN 1 ELSE 0 END) as false_negative_feedback,
                    SUM(CASE WHEN feedback_type = 'unsure' THEN 1 ELSE 0 END) as unsure_feedback
                FROM feedback
            ''')
            
            stats = cursor.fetchone()
            
            # Get feedback by confidence ranges
            cursor.execute('''
                SELECT 
                    CASE 
                        WHEN original_confidence >= 80 THEN 'high'
                        WHEN original_confidence >= 50 THEN 'medium'
                        ELSE 'low'
                    END as confidence_range,
                    COUNT(*) as total,
                    SUM(CASE WHEN feedback_type IN ('correct', 'false_positive') THEN 1 ELSE 0 END) as positive_feedback
                FROM feedback
                WHERE original_confidence IS NOT NULL
                GROUP BY confidence_range
            ''')
            
            confidence_stats = cursor.fetchall()
            conn.close()
            
            total_feedback = stats[0] or 0
            correct_feedback = stats[1] or 0
            
            return {
                'total_feedback': total_feedback,
                'correct_feedback': correct_feedback,
                'incorrect_feedback': stats[2] or 0,
                'false_positive_feedback': stats[3] or 0,
                'false_negative_feedback': stats[4] or 0,
                'unsure_feedback': stats[5] or 0,
                'accuracy_rate': (correct_feedback / total_feedback * 100) if total_feedback > 0 else 0,
                'confidence_breakdown': {
                    row[0]: {'total': row[1], 'positive_feedback': row[2], 'accuracy': (row[2] / row[1] * 100) if row[1] > 0 else 0}
                    for row in confidence_stats
                }
            }
        except Exception as e:
            logging.error(f"Error getting feedback stats: {e}")
            return {}
    
    def save_domain_intelligence(self, domain: str, whois_data: Dict, dns_records: Dict, 
                                registration_date: str = None, registrar: str = None,
                                creation_days_ago: int = None) -> bool:
        """Save domain intelligence data."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO domain_intelligence 
                (domain, whois_data, dns_records, registration_date, registrar, 
                 creation_days_ago, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                domain,
                json.dumps(whois_data),
                json.dumps(dns_records),
                registration_date,
                registrar,
                creation_days_ago
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logging.error(f"Error saving domain intelligence: {e}")
            return False
    
    def get_domain_intelligence(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain intelligence data."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT domain, whois_data, dns_records, registration_date, registrar,
                       creation_days_ago, created_at, updated_at
                FROM domain_intelligence WHERE domain = ?
            ''', (domain,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'domain': row[0],
                    'whois_data': json.loads(row[1]) if row[1] else {},
                    'dns_records': json.loads(row[2]) if row[2] else {},
                    'registration_date': row[3],
                    'registrar': row[4],
                    'creation_days_ago': row[5],
                    'created_at': row[6],
                    'updated_at': row[7]
                }
            return None
        except Exception as e:
            logging.error(f"Error getting domain intelligence: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall scan statistics."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Get basic counts
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_scanned,
                    SUM(CASE WHEN judgment LIKE '%malicious%' OR judgment LIKE '%dangerous%' THEN 1 ELSE 0 END) as dangerous_count,
                    SUM(CASE WHEN judgment LIKE '%potential%' OR judgment LIKE '%suspicious%' THEN 1 ELSE 0 END) as potential_count,
                    SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) as error_count
                FROM scan_results
            ''')
            
            stats = cursor.fetchone()
            
            # Get confidence distribution
            cursor.execute('''
                SELECT 
                    CASE 
                        WHEN confidence >= 80 THEN 'high_confidence'
                        WHEN confidence >= 50 THEN 'medium_confidence'
                        WHEN confidence IS NOT NULL THEN 'low_confidence'
                        ELSE 'no_confidence'
                    END as confidence_range,
                    COUNT(*)
                FROM scan_results
                GROUP BY confidence_range
            ''')
            
            confidence_dist = dict(cursor.fetchall())
            conn.close()
            
            total = stats[0] or 0
            dangerous = stats[1] or 0
            potential = stats[2] or 0
            errors = stats[3] or 0
            safe_count = max(0, total - dangerous - potential - errors)
            
            return {
                'total_scanned': total,
                'dangerous_count': dangerous,
                'potential_count': potential,
                'safe_count': safe_count,
                'error_count': errors,
                'confidence_distribution': confidence_dist
            }
        except Exception as e:
            logging.error(f"Error getting statistics: {e}")
            return {}
    
    def advanced_query(self, filters: Dict[str, Any], limit: int = None, offset: int = None) -> List[Dict[str, Any]]:
        """Advanced query with multiple filters and sorting options."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            query = '''
                SELECT url, judgment, confidence, illegal_rate, text_result, vision_results, server_info,
                       shadowdoor_links, vulnerabilities, new_keywords, error, cached,
                       created_at, updated_at
                FROM scan_results WHERE 1=1
            '''
            params = []
            
            # Apply filters
            if 'url_contains' in filters:
                query += ' AND url LIKE ?'
                params.append(f'%{filters["url_contains"]}%')
            
            if 'judgment_contains' in filters:
                query += ' AND judgment LIKE ?'
                params.append(f'%{filters["judgment_contains"]}%')
            
            if 'confidence_min' in filters:
                query += ' AND confidence >= ?'
                params.append(filters['confidence_min'])
            
            if 'confidence_max' in filters:
                query += ' AND confidence <= ?'
                params.append(filters['confidence_max'])
            
            if 'has_error' in filters:
                if filters['has_error']:
                    query += ' AND error IS NOT NULL'
                else:
                    query += ' AND error IS NULL'
            
            if 'date_from' in filters:
                query += ' AND created_at >= ?'
                params.append(filters['date_from'])
            
            if 'date_to' in filters:
                query += ' AND created_at <= ?'
                params.append(filters['date_to'])
            
            # Sorting
            sort_by = filters.get('sort_by', 'created_at')
            sort_order = filters.get('sort_order', 'DESC')
            if sort_by in ['url', 'judgment', 'confidence', 'created_at', 'updated_at']:
                query += f' ORDER BY {sort_by} {sort_order}'
            
            # Pagination
            if limit:
                query += ' LIMIT ?'
                params.append(limit)
            
            if offset:
                query += ' OFFSET ?'
                params.append(offset)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for row in rows:
                results.append({
                    'url': row[0],
                    'judgment': row[1],
                    'confidence': row[2],
                    'illegal_rate': row[3],
                    'text_result': row[4],
                    'vision_results': json.loads(row[5]) if row[5] else [],
                    'server_info': json.loads(row[6]) if row[6] else {},
                    'shadowdoor_links': json.loads(row[7]) if row[7] else [],
                    'vulnerabilities': json.loads(row[8]) if row[8] else [],
                    'new_keywords': json.loads(row[9]) if row[9] else [],
                    'error': row[10],
                    'cached': row[11],
                    'created_at': row[12],
                    'updated_at': row[13]
                })
            return results
        except Exception as e:
            logging.error(f"Error in advanced query: {e}")
            return []
    
    def get_domain_statistics(self) -> Dict[str, Any]:
        """Get statistics grouped by domain."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Extract domain from URL and group statistics
            cursor.execute('''
                SELECT 
                    CASE 
                        WHEN url LIKE 'http://%' THEN 
                            SUBSTR(url, 8, INSTR(SUBSTR(url, 8), '/') - 1)
                        WHEN url LIKE 'https://%' THEN 
                            SUBSTR(url, 9, INSTR(SUBSTR(url, 9), '/') - 1)
                        ELSE url
                    END as domain,
                    COUNT(*) as total_scans,
                    AVG(confidence) as avg_confidence,
                    AVG(illegal_rate) as avg_illegal_rate,
                    SUM(CASE WHEN judgment LIKE '%malicious%' OR judgment LIKE '%dangerous%' THEN 1 ELSE 0 END) as dangerous_count,
                    SUM(CASE WHEN judgment LIKE '%potential%' OR judgment LIKE '%suspicious%' THEN 1 ELSE 0 END) as potential_count,
                    MAX(created_at) as last_scanned
                FROM scan_results
                WHERE domain IS NOT NULL AND domain != ''
                GROUP BY domain
                ORDER BY total_scans DESC
                LIMIT 50
            ''')
            
            domain_stats = cursor.fetchall()
            conn.close()
            
            return {
                'top_domains': [
                    {
                        'domain': row[0],
                        'total_scans': row[1],
                        'avg_confidence': round(row[2] or 0, 2),
                        'avg_illegal_rate': round(row[3] or 0, 2),
                        'dangerous_count': row[4],
                        'potential_count': row[5],
                        'last_scanned': row[6]
                    }
                    for row in domain_stats
                ]
            }
        except Exception as e:
            logging.error(f"Error getting domain statistics: {e}")
            return {'top_domains': []}
    
    def get_time_series_stats(self, days: int = 30) -> Dict[str, Any]:
        """Get statistics over time."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute(f'''
                SELECT 
                    DATE(created_at) as scan_date,
                    COUNT(*) as total_scans,
                    SUM(CASE WHEN judgment LIKE '%malicious%' OR judgment LIKE '%dangerous%' THEN 1 ELSE 0 END) as dangerous_count,
                    SUM(CASE WHEN judgment LIKE '%potential%' OR judgment LIKE '%suspicious%' THEN 1 ELSE 0 END) as potential_count,
                    AVG(confidence) as avg_confidence
                FROM scan_results
                WHERE created_at >= date('now', '-{days} days')
                GROUP BY DATE(created_at)
                ORDER BY scan_date
            ''')
            
            time_series = cursor.fetchall()
            conn.close()
            
            return {
                'time_series': [
                    {
                        'date': row[0],
                        'total_scans': row[1],
                        'dangerous_count': row[2],
                        'potential_count': row[3],
                        'avg_confidence': round(row[4] or 0, 2)
                    }
                    for row in time_series
                ]
            }
        except Exception as e:
            logging.error(f"Error getting time series stats: {e}")
            return {'time_series': []}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics for PDF reports."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Get basic counts
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_scanned,
                    AVG(confidence) as avg_confidence,
                    AVG(illegal_rate) as avg_illegal_rate,
                    SUM(CASE WHEN judgment LIKE '%safe%' THEN 1 ELSE 0 END) as safe_count,
                    SUM(CASE WHEN judgment LIKE '%potential%' OR judgment LIKE '%suspicious%' THEN 1 ELSE 0 END) as potential_count,
                    SUM(CASE WHEN judgment LIKE '%malicious%' OR judgment LIKE '%dangerous%' THEN 1 ELSE 0 END) as dangerous_count,
                    SUM(CASE WHEN error IS NOT NULL AND error != '' THEN 1 ELSE 0 END) as error_count
                FROM scan_results
            ''')
            
            row = cursor.fetchone()
            conn.close()
            
            return {
                'total_scanned': row[0] or 0,
                'avg_confidence': round(row[1] or 0, 2),
                'avg_illegal_rate': round(row[2] or 0, 2),
                'safe_count': row[3] or 0,
                'potential_count': row[4] or 0,
                'dangerous_count': row[5] or 0,
                'error_count': row[6] or 0
            }
        except Exception as e:
            logging.error(f"Error getting statistics: {e}")
            return {
                'total_scanned': 0,
                'avg_confidence': 0,
                'avg_illegal_rate': 0,
                'safe_count': 0,
                'potential_count': 0,
                'dangerous_count': 0,
                'error_count': 0
            }
