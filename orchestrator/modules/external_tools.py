"""
External Tools Module
Wrappers for third-party command-line tools (Amass, theHarvester)
"""

import subprocess
import shutil
import re
import os
from typing import Set, Tuple
from config import config

class ExternalTools:
    def __init__(self, target):
        self.target = target
        self.amass_path = shutil.which("amass")
        self.harvester_path = shutil.which("theHarvester")

    def _run_command(self, cmd: list) -> str:
        """Run a command and return stdout"""
        try:
            print(f"    - Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=300 # 5 minute timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"    [!] Command timed out: {' '.join(cmd)}")
            return ""
        except Exception as e:
            print(f"    [!] Command execution error: {e}")
            return ""

    def run_amass_passive(self) -> Set[str]:
        """Run Amass in passive mode"""
        subdomains = set()
        
        if not self.amass_path:
            print("    [!] Amass not found in PATH")
            return subdomains
        
        print("[+] Running Amass (Passive Mode)...")
        
        # amas enum -passive -d domain
        cmd = [self.amass_path, "enum", "-passive", "-d", self.target]
        output = self._run_command(cmd)
        
        if output:
            # Parse output for subdomains
            # Amass output format can vary, but usually lists domains one per line or in brackets
            # We'll just regex for subdomains of the target
            matches = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.target) + r')', output)
            for match in matches:
                sub = match.lower().strip()
                if sub != self.target:
                    subdomains.add(sub)
            
            print(f"    - Amass found {len(subdomains)} subdomains")
            
        return subdomains

    def run_theharvester(self) -> Tuple[Set[str], Set[str]]:
        """Run theHarvester for emails and subdomains"""
        emails = set()
        subdomains = set()
        
        if not self.harvester_path:
            print("    [!] theHarvester not found in PATH")
            return emails, subdomains
            
        print("[+] Running theHarvester...")
        
        # theHarvester -d domain -b all
        # Note: 'all' might take a long time and require keys for some sources.
        # We might want to limit sources or rely on its own passive configuration.
        # For now, we'll try 'anubis,baidu,bing,binaryedge,bingapi,bufferoverun,censys,certspotter,crtsh,dnsdumpster,duckduckgo,fullhunt,github-code,google,hackertarget,hunter,intelx,linkedin,n45ht,omnisint,otx,pentesttools,projectdiscovery,qwant,rapiddns,rocketreach,securityTrails,sublist3r,threatcrowd,threatminer,trello,twitter,urlscan,virustotal,yahoo,zoomeye'
        # But 'all' is simpler for the wrapper.
        
        cmd = [self.harvester_path, "-d", self.target, "-b", "all", "-l", "500", "-f", "harvester_results"]
        
        # clean up previous results if exists
        if os.path.exists("harvester_results.json"):
            try:
                os.remove("harvester_results.json")
            except:
                pass
                
        output = self._run_command(cmd)
        
        # Parse output directly from stdout if XML/JSON export fails or distinct from stdout
        # Emails
        email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', output)
        for email in email_matches:
             if not email.endswith(('.png', '.jpg', '.jpeg', '.gif', '.js', '.css')) and self.target in email: # simple filter
                 emails.add(email.lower())
        
        # Subdomains
        sub_matches = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.target) + r')', output)
        for sub in sub_matches:
            sub = sub.lower().strip()
            if sub != self.target:
                subdomains.add(sub)
                
        print(f"    - theHarvester found {len(emails)} emails and {len(subdomains)} subdomains")
        
        # Cleanup
        if os.path.exists("harvester_results.json"):
             try:
                os.remove("harvester_results.json")
             except:
                pass
        if os.path.exists("harvester_results.xml"):
             try:
                os.remove("harvester_results.xml")
             except:
                pass
                
        return emails, subdomains
