"""
Search Intelligence Module
Google Dorks, GitHub code search, and Pastebin monitoring
"""

import requests
import sqlite3
import time
from config import config

class SearchIntelligence:
    def __init__(self, target, target_id):
        self.target = target
        self.target_id = target_id
        self.github_token = config.GITHUB_TOKEN
    
    def google_dork_search(self):
        """Execute Google Dorks to find sensitive information"""
        results = []
        
        # Define dork queries
        dorks = [
            f'site:{self.target} filetype:pdf',
            f'site:{self.target} filetype:xls OR filetype:xlsx',
            f'site:{self.target} filetype:doc OR filetype:docx',
            f'site:{self.target} inurl:admin',
            f'site:{self.target} inurl:login',
            f'site:{self.target} ext:sql OR ext:log',
            f'site:{self.target} ext:env OR ext:config',
            f'site:{self.target} "index of"',
            # GitHub Dorks
            f'site:github.com "{self.target}"',
            f'site:github.com "{self.target}" password',
            f'site:github.com "{self.target}" api_key',
            f'site:github.com "{self.target}" secret',
        ]
        
        print(f"    - Executing {len(dorks)} Google Dorks...")
        
        try:
            from googlesearch import search
            
            for dork in dorks[:3]:  # Limit to 3 dorks to avoid rate limiting
                try:
                    print(f"      Searching: {dork}")
                    
                    # Get top 5 results for each dork
                    for result_url in search(dork, num_results=5, sleep_interval=2):
                        results.append({
                            'source': 'Google',
                            'search_type': 'dork',
                            'query': dork,
                            'result_url': result_url,
                            'risk_level': self.assess_risk_level(dork, result_url)
                        })
                    
                    time.sleep(2)  # Rate limiting
                    
                except Exception as e:
                    print(f"      [!] Dork failed: {e}")
                    continue
                    
        except ImportError:
            print("    [!] googlesearch-python not installed, skipping Google Dorks")
        except Exception as e:
            print(f"    [!] Google Dork error: {e}")
        
        return results
    
    def github_code_search(self):
        """Search GitHub for code/secrets related to target"""
        results = []
        
        if not self.github_token:
            print("    [!] GitHub token not configured, skipping code search")
            return results
        
        try:
            from github import Github
            
            g = Github(self.github_token)
            
            # Search queries
            queries = [
                f'{self.target}',
                f'{self.target} password',
                f'{self.target} api_key',
                f'{self.target} secret',
            ]
            
            print(f"    - Searching GitHub repositories...")
            
            for query in queries[:2]:  # Limit to 2 queries
                try:
                    # Search code
                    code_results = g.search_code(query, order='desc')
                    
                    count = 0
                    for item in code_results:
                        if count >= 5:
                            break
                        results.append({
                            'source': 'GitHub',
                            'search_type': 'code',
                            'query': query,
                            'result_url': item.html_url,
                            'title': f"{item.repository.full_name}:{item.path}",
                            'snippet': item.repository.description or '',
                            'risk_level': 'High' if 'password' in query or 'secret' in query else 'Medium'
                        })
                        count += 1
                    
                    time.sleep(2)  # Rate limiting
                    
                except Exception as e:
                    print(f"      [!] GitHub search failed: {e}")
                    break
                    
        except ImportError:
            print("    [!] PyGithub not installed, skipping GitHub search")
        except Exception as e:
            print(f"    [!] GitHub error: {e}")
        
        return results
    
    def pastebin_search(self):
        """Search Pastebin for mentions (limited without API)"""
        results = []
        
        try:
            # Use Google to search Pastebin
            search_url = f"https://www.google.com/search?q=site:pastebin.com+{self.target}"
            headers = {'User-Agent': config.USER_AGENT}
            
            res = requests.get(search_url, headers=headers, timeout=10)
            
            if res.status_code == 200:
                # Simple check if domain appears in results
                if self.target.lower() in res.text.lower():
                    results.append({
                        'source': 'Pastebin',
                        'search_type': 'paste',
                        'query': f'site:pastebin.com {self.target}',
                        'result_url': search_url,
                        'title': 'Potential pastes found',
                        'risk_level': 'High'
                    })
                    
        except Exception as e:
            print(f"    [!] Pastebin search failed: {e}")
        
        return results
    
    def assess_risk_level(self, query, url):
        """Determine risk level based on query and URL"""
        high_risk_keywords = ['password', 'secret', 'api', 'key', 'token', 'login', 'admin', 'sql', 'log', 'env', 'config']
        medium_risk_keywords = ['pdf', 'doc', 'xls', 'backup']
        
        query_lower = query.lower()
        url_lower = url.lower()
        
        if any(keyword in query_lower or keyword in url_lower for keyword in high_risk_keywords):
            return 'High'
        elif any(keyword in query_lower or keyword in url_lower for keyword in medium_risk_keywords):
            return 'Medium'
        else:
            return 'Low'
    
    def store_search_result(self, result):
        """Store search result in database"""
        try:
            conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO search_results (target_id, source, search_type, query, result_url, 
                                           title, snippet, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.target_id,
                result.get('source', ''),
                result.get('search_type', ''),
                result.get('query', ''),
                result.get('result_url', ''),
                result.get('title', ''),
                result.get('snippet', ''),
                result.get('risk_level', 'Low')
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"    [!] Database error: {e}")
    
    def execute(self):
        """Run complete search intelligence gathering"""
        print("[+] Running Search Intelligence (Dorks & Code Search)...")
        
        if not config.ENABLE_SEARCH_INTEL:
            print("    [!] Search Intelligence disabled in configuration")
            return
        
        all_results = []
        
        # Google Dorks
        print("    - Running Google Dorks...")
        dork_results = self.google_dork_search()
        all_results.extend(dork_results)
        
        # GitHub Search
        print("    - Searching GitHub...")
        github_results = self.github_code_search()
        all_results.extend(github_results)
        
        # Pastebin Search
        print("    - Checking Pastebin...")
        paste_results = self.pastebin_search()
        all_results.extend(paste_results)
        
        # Store and display results
        if all_results:
            print(f"    - Found {len(all_results)} search intelligence results:")
            
            for result in all_results:
                risk = result.get('risk_level', 'Low')
                symbol = '🔴' if risk == 'High' else '🟡' if risk == 'Medium' else '🟢'
                print(f"      {symbol} [{risk}] {result.get('title', result.get('result_url', '')[:50])}")
                
                self.store_search_result(result)
        else:
            print("    - No sensitive information found in search engines")
