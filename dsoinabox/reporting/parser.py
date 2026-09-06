import json
import os
import textwrap
from abc import ABC, abstractmethod

from ..fingerprints.checkov import _extract_severity
from ..fingerprints.checkov import fingerprint_findings as checkov_fingerprint_findings
from ..fingerprints.grype import fingerprint_findings as grype_fingerprint_findings
from ..fingerprints.opengrep import fingerprint_findings as opengrep_fingerprint_findings
from ..fingerprints.trufflehog import fingerprint_findings as trufflehog_fingerprint_findings
from ..waivers.apply import active_findings
from .fields import relativize_path

#threshold mapping: cleaner than if/elif chain
#old format for semgrep/opengrep severity thresholds:
#warning = medium, error = high
_THRESHOLD_MAP = {
    None: ("error", "warning", "info", "low", "medium", "high", "critical"),
    "none": ("error", "warning", "info", "low", "medium", "high", "critical"),
    "info": ("error", "warning", "info", "low", "medium", "high", "critical"),
    "low": ("warning", "error", "low", "medium", "high", "critical"),
    "medium": ("warning", "error", "medium", "high", "critical"),
    "warning": ("warning", "error", "medium", "high", "critical"),
    "high": ("error", "high", "critical"),
    "error": ("error", "high", "critical"),
    "critical": ("critical",),
}

def get_fail_thresholds(threshold: str):
    """get fail thresholds for a given severity threshold
    
    old format for semgrep/opengrep severity thresholds:
    - warning = medium, error = high
    """
    return _THRESHOLD_MAP.get(threshold, _THRESHOLD_MAP[None])


class BaseParser(ABC):
    """base class for report parsers with common functionality"""
    
    def __init__(self, report_directory: str, report_filename: str, data: dict = None):
        self.report_path = os.path.join(report_directory, report_filename)
        if data is None:
            self.data = self.load_report()
        else:
            self.data = data
    
    def report_exists(self):
        return os.path.exists(self.report_path)
    
    def load_report(self):
        if not self.report_exists():
            return None
        with open(self.report_path, 'r') as file:
            return json.load(file)
    
    @abstractmethod
    def findings_that_exceed_threshold(self, threshold: str):
        """return findings that exceed the given threshold. must be implemented by subclasses"""
        pass
    
    def apply_threshold(self, threshold: str):
        """filter data to only include findings that exceed threshold."""
        modified_data = self.data.copy()
        findings_key = self._get_findings_key()
        modified_data[findings_key] = self.findings_that_exceed_threshold(threshold)
        self.data = modified_data
        return self.data
    
    @abstractmethod
    def _get_findings_key(self) -> str:
        """return the key in data dict that contains findings (e.g., 'results', 'matches')"""
        pass

class OpengrepParser(BaseParser):
    def __init__(self, report_directory: str, report_filename: str, data: dict = None):
        super().__init__(report_directory, report_filename, data)
    
    def _get_findings_key(self) -> str:
        return "results"
    
    def findings_that_exceed_threshold(self, threshold: str):
        """
        opengrep severities:
            new rules:
                Low, Medium, High, Critical

            old rules:
                Error - High severity
                Warning - Medium severity
                Info - Low severity
        """
        fail_thresholds = get_fail_thresholds(threshold)
        failed_findings = []
        for result in self.data.get("results", []):
            if result.get("extra", {}).get("severity", "unknown").lower() in fail_thresholds:
                failed_findings.append(result)
        return failed_findings
    
    def fingerprint_findings(self, source_path: str, project_id: str | None = None):
        self.data = opengrep_fingerprint_findings(self.data, source_path, project_id=project_id)
        return self.data
    
    def cli_display_findings(self):
        print(textwrap.dedent(
            """
            --------------------------------
            OpenGrep Findings
            --------------------------------
            Severity:
            Rule-ID:
            Description:
            Reference:
            Path: Line
            Finding Snippet:
            Fingerprint-Rule:
            Fingerprint-Exact:
            Fingerprint-CTX:
            --------------------------------
            Fingerprint Types:
            - RULE: Hash-based identifier derived from the rule id
            - EXACT: Location-bound identifier derived from the rule id,
            normalized file content hash, and byte span of the finding.
            - CTX: Contextual identifier derived from the rule id,
            normalized relative file path, and a hash of the redacted
            surrounding context window. This fingerprint remains valid
            through small edits or whitespace changes but loses specificity
            if the finding moves significantly.
            """))
        for finding in active_findings(self.data["results"]):
    
            print(textwrap.dedent(f"""
                ######### Finding Details ##########
                Severity: {finding.get('extra', {}).get('severity', '')}
                Rule-ID: {finding.get('check_id', '')}
                Description: {finding.get('extra', {}).get('message', '')}
                Reference: {finding.get('extra', {}).get('metadata', {}).get('source', '')}
                Path: {finding.get('path', '')}:{finding.get('line', '')}
                ---------- Finding Snippet ----------
                {finding.get('extra', {}).get('lines', '')}
                ---------- Fingerprints -------------
                Fingerprint-Rule: {finding.get('fingerprints', {}).get('rule', '')}
                Fingerprint-Exact: {finding.get('fingerprints', {}).get('exact', '')}
                Fingerprint-Context: {finding.get('fingerprints', {}).get('ctx', '')}
            """))
            print()



class GrypeParser(BaseParser):
    def __init__(self, report_directory: str, report_filename: str, data: dict = None):
        super().__init__(report_directory, report_filename, data)
    
    def _get_findings_key(self) -> str:
        return "matches"
    
    def findings_that_exceed_threshold(self, threshold: str):
        fail_thresholds = get_fail_thresholds(threshold)
        failed_findings = []
        for match in self.data.get("matches", []):
            if match.get("vulnerability", {}).get("severity", "unknown").lower() in fail_thresholds:
                failed_findings.append(match)
        return failed_findings
    
    def fingerprint_findings(self, project_id: str | None = None):
        self.data = grype_fingerprint_findings(self.data, project_id=project_id)
        return self.data

    def cli_display_findings(self):
        print(textwrap.dedent(
            """
            --------------------------------
            Grype Findings
            --------------------------------
            Severity:
            Package:
            Version:
            Vulnerability:
            Description:
            Reference:
            Fix:
            Locations (Path):
            Namespace:
            Fingerprint-PKG:
            Fingerprint-Exact:
            Fingerprint-CTX:

            Fingerprint Types:
            - PKG: Hash-based identifier derived from the package name, version, and namespace
            - EXACT: Location-bound identifier derived from the package name, version, and namespace
            - CTX: Contextual identifier derived from the package name, version, and namespace
            """))
        for finding in active_findings(self.data.get("matches", [])):
            print(textwrap.dedent(f"""
                Severity: {finding.get('vulnerability', {}).get('severity', '')}
                Package: {finding.get('artifact', {}).get('name', '')}
                Version: {finding.get('artifact', {}).get('version', '')}
                Vulnerability: {finding.get('vulnerability', {}).get('id', '')}
                Description: {finding.get('vulnerability', {}).get('description', '')}
                Reference: {finding.get('vulnerability', {}).get('dataSource', '')}
                Fix: {finding.get('vulnerability', {}).get('fix', {}).get('versions', '')}
                Locations (Path): {finding.get('artifact', {}).get('locations', [{}])[0].get('path', '')}
                Namespace: {finding.get('vulnerability', {}).get('namespace', '')}
                Fingerprint-PKG: {finding.get('fingerprints', {}).get('pkg', '')}
                Fingerprint-Exact: {finding.get('fingerprints', {}).get('exact', '')}
                Fingerprint-CTX: {finding.get('fingerprints', {}).get('ctx', '')}
            """))

class TrufflehogParser(BaseParser):
    def __init__(self, report_directory: str, report_filename: str, data: dict = None):
        super().__init__(report_directory, report_filename, data)
    
    def _get_findings_key(self) -> str:
        #trufflehog doesn't use threshold filtering, but need to implement abstract method
        return "results"  #not used, but satisfies interface
    
    def findings_that_exceed_threshold(self, threshold: str):
        #trufflehog doesn't filter by threshold - return all findings
        return self.data if isinstance(self.data, list) else []

    def get_trufflehog_file_path(self, finding: dict) -> str:
        data = (finding.get("SourceMetadata") or {}).get("Data") or {}

        #--- case 1: git scan ---
        if "Git" in data:
            git_data = data["Git"]
            repo_root = git_data.get("repository_local_path") or "."
            file_rel = git_data.get("file")
            if file_rel:
                return relativize_path(file_rel, repo_root)

        #--- case 2: filesystem scan ---
        if "Filesystem" in data:
            fs_data = data["Filesystem"]
            base = fs_data.get("base_path") or "."
            path = fs_data.get("file") or fs_data.get("file_path") or fs_data.get("path")
            if path:
                return relativize_path(path, base)

        raise ValueError("Unable to determine file path from Trufflehog finding")
    
    def fingerprint_findings(self, source_path: str, project_id: str | None = None):
        self.data = trufflehog_fingerprint_findings(self.data, source_path, project_id=project_id)
        return self.data
        
    def findings(self):
        return self.data

    def cli_display_findings(self):
        print(textwrap.dedent(
            """
            --------------------------------
            Trufflehog Findings
            --------------------------------
            File : Line
            Type(Detector):
            Finding:
            Fingerprint-Secret:
            Fingerprint-Exact:
            Fingerprint-CTX:
            --------------------------------
            Fingerprint Types:
            - SECRET: Hash-based identifier derived from the normalized secret value
            (via HMAC-SHA256 with a project-scoped key). Stable across file moves
            and commits, and safe to store publicly since the raw secret is never exposed.
            This is the preferred fingerprint type for waivers and deduplication.

            - EXACT: Location-bound identifier derived from the detector name,
            normalized file content hash, and byte span of the finding.
            This binds tightly to a specific file revision and match location,
            ensuring precise scoping but breaking if the file changes.

            - CTX: Contextual identifier derived from the detector name,
            normalized relative file path, and a hash of the redacted
            surrounding context window. This fingerprint remains valid
            through small edits or whitespace changes but loses specificity
            if the finding moves significantly.
            """))
        for finding in active_findings(self.data):
            file_path = self.get_trufflehog_file_path(finding)
            print(textwrap.dedent(f"""
                Path: {file_path}:{finding.get('line', '')}
                Type: {finding.get('DetectorName', '')}
                Finding: {finding.get('RawV2', '')}
                Fingerprint-Secret: {finding.get('fingerprints', {}).get('secret', '')}
                Fingerprint-Exact: {finding.get('fingerprints', {}).get('exact', '')}
                Fingerprint-CTX: {finding.get('fingerprints', {}).get('ctx', '')}
            """))

class CheckovParser(BaseParser):
    def __init__(self, report_directory: str, report_filename: str, data: dict = None):
        super().__init__(report_directory, report_filename, data)
    
    def _get_findings_key(self) -> str:
        return "results"
    
    def _get_results_from_sarif(self) -> list:
        """extract results from sarif format"""
        runs = self.data.get("runs", [])
        if not runs:
            return []
        return runs[0].get("results", [])
    
    def findings_that_exceed_threshold(self, threshold: str):
        """filter sarif results by severity threshold"""
        fail_thresholds = get_fail_thresholds(threshold)
        failed_findings = []
        results = self._get_results_from_sarif()
        for result in results:
            severity = _extract_severity(result, self.data)
            if severity.lower() in fail_thresholds:
                failed_findings.append(result)
        return failed_findings
    
    def apply_threshold(self, threshold: str):
        """filter data to only include findings that exceed threshold"""
        #override base class to handle sarif format
        filtered_results = self.findings_that_exceed_threshold(threshold)
        runs = self.data.get("runs", [])
        if runs:
            runs[0]["results"] = filtered_results
        return self.data
    
    def fingerprint_findings(self, source_path: str, project_id: str | None = None):
        self.data = checkov_fingerprint_findings(self.data, source_path, project_id=project_id)
        return self.data
    
    def cli_display_findings(self):
        print(textwrap.dedent(
            """
            --------------------------------
            Checkov Findings
            --------------------------------
            Severity:
            Rule-ID:
            Description:
            Path: Line
            Finding Snippet:
            Fingerprint-Rule:
            Fingerprint-Exact:
            Fingerprint-CTX:
            --------------------------------
            Fingerprint Types:
            - RULE: Hash-based identifier derived from the rule id
            - EXACT: Location-bound identifier derived from the rule id,
            normalized file path, and line numbers.
            - CTX: Contextual identifier derived from the rule id,
            normalized relative file path, and a hash of the code snippet.
            This fingerprint remains valid through small edits or whitespace changes.
            """))
        results = active_findings(self._get_results_from_sarif())
        for result in results:
            # Extract information from SARIF result
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "error")
            message = result.get("message", {})
            message_text = message.get("text", "") if isinstance(message, dict) else str(message)
            
            # Extract location info
            locations = result.get("locations", [])
            file_path = ""
            start_line = 0
            snippet = ""
            if locations:
                physical_location = locations[0].get("physicalLocation", {})
                artifact_location = physical_location.get("artifactLocation", {})
                file_path = artifact_location.get("uri", "")
                region = physical_location.get("region", {})
                start_line = region.get("startLine", 0)
                snippet_obj = region.get("snippet", {})
                if isinstance(snippet_obj, dict):
                    snippet = snippet_obj.get("text", "")
            
            # Get severity
            severity = _extract_severity(result, self.data)
            
            print(textwrap.dedent(f"""
                ######### Finding Details ##########
                Severity: {severity}
                Rule-ID: {rule_id}
                Level: {level}
                Description: {message_text}
                Path: {file_path}:{start_line}
                ---------- Finding Snippet ----------
                {snippet}
                ---------- Fingerprints -------------
                Fingerprint-Rule: {result.get('fingerprints', {}).get('rule', '')}
                Fingerprint-Exact: {result.get('fingerprints', {}).get('exact', '')}
                Fingerprint-Context: {result.get('fingerprints', {}).get('ctx', '')}
            """))
            print()
