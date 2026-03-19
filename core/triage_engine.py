from core.triage.filter import TriageFilter
from core.triage.poc_generator import PoCGenerator
from core.triage.reporter import BugReporter

class TriageEngine:
    """
    Facade Atómico para BugBot TriageEngine.
    Delega el filtrado y reporte a módulos especializados.
    """
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.reporter = BugReporter(target_domain)
        self.filter = TriageFilter()
        self.poc = PoCGenerator()

    def generate_curl_poc(self, url: str, method: str = "GET", headers: dict = None, payload: str = None) -> str:
        return self.poc.generate_curl(url, method, headers, payload)

    def is_false_positive(self, file_path: str, context_string: str) -> bool:
        return self.filter.is_false_positive(file_path, context_string)

    def calculate_severity(self, bug_type: str) -> str:
        return self.reporter.get_severity(bug_type)

    def generate_hackerone_report(self, bug_data: dict) -> str:
        return self.reporter.generate_h1(bug_data)
        
    def in_scope(self, target_url: str, allowed_domains: list) -> bool:
        return any(domain in target_url for domain in allowed_domains)
