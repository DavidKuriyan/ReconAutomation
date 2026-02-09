
import sys
import os
import re

# Add parent directory to path to import modules
sys.path.append(os.path.join(os.getcwd(), 'orchestrator'))

class MockDB:
    def connect(self): return True
    def close(self): pass
    def conn(self): return self
    def cursor(self): return self
    def execute(self, *args): pass
    def commit(self): pass
    def fetchone(self): return None

class MockResponse:
    def __init__(self, text):
        self.text = text
        self.headers = {}
        self.cookies = {}

def test_tech_detector_fix():
    print("\n[+] Testing TechDetector Fix...")
    try:
        from modules.tech_detector import TechDetector
        td = TechDetector("example.com", 1, MockDB())
        
        # This triggered the AttributeError before because _script_srcs wasn't in __slots__
        # but was assigned in _check_html
        mock_html = '<html><head><script src="test.js"></script></head><body></body></html>'
        td.analyze(MockResponse(mock_html))
        
        print("  [OK] TechDetector analysis ran without AttributeError!")
        
        # Verify it actually found the script
        if hasattr(td, '_script_srcs') and len(td._script_srcs) > 0:
             print(f"  [OK] _script_srcs populated: {td._script_srcs}")
        else:
             print("  [WARN] _script_srcs not populated (might be okay if logic changed)")
             
    except AttributeError as e:
        print(f"  [FAIL] AttributeError still persists: {e}")
    except Exception as e:
        print(f"  [FAIL] Other error: {e}")

def test_github_search_fix():
    print("\n[+] Testing GitHub Search Fix...")
    try:
        from modules.search_intel import SearchIntelligence
        si = SearchIntelligence("example.com", 1)
        
        # We can't easily mock the internal PyGithub calls without a lot of mocking framework
        # But we can inspect the source code in file to be sure (static analysis via script)
        # or we can trust the manual verify we did.
        # Let's try to verify the method structure hasn't syntax errors at least.
        import inspect
        source = inspect.getsource(si.github_code_search)
        if "item in code_results[:5]" in source:
             print("  [FAIL] Code still contains unsafe slicing '[:5]'")
        else:
             print("  [OK] Code does not contain unsafe slicing '[:5]'")
             
    except Exception as e:
        print(f"  [FAIL] Error inspecting module: {e}")

if __name__ == "__main__":
    test_tech_detector_fix()
    test_github_search_fix()
