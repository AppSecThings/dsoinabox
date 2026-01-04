"""dsoinabox cli implementation"""

from __future__ import annotations

import argparse
import sys
import os
import shutil
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .utils.deterministic import utcnow

from .scanners.sbom.syft import show_version as syft_show_version
from .scanners.sbom.syft import show_help as syft_show_help
from .scanners.sbom.syft import dir_scan as syft_dir_scan

from .scanners.sca.grype import show_version as grype_show_version
from .scanners.sca.grype import show_help as grype_show_help
from .scanners.sca.grype import run_scan as grype_run_scan

from .scanners.secrets.trufflehog import show_version as trufflehog_show_version
from .scanners.secrets.trufflehog import run_scan as trufflehog_run_scan
from .scanners.secrets.trufflehog import show_help as trufflehog_show_help


from .scanners.sast.opengrep import show_version as opengrep_show_version   
from .scanners.sast.opengrep import show_help as opengrep_show_help
from .scanners.sast.opengrep import run_scan as opengrep_run_scan

from .scanners.iac.checkov import show_version as checkov_show_version
from .scanners.iac.checkov import show_help as checkov_show_help
from .scanners.iac.checkov import run_scan as checkov_run_scan

from .scanners.base import ScannerError

from .reporting.parser import OpengrepParser, SyftParser, GrypeParser, TrufflehogParser, CheckovParser
from .reporting.report_builder import report_builder

from .utils.git import GitRepoInfo, set_git_safe_directory
from .utils.project_id import derive_project_id, is_git
from .utils.environment import is_running_in_docker, check_tool_available

from .waivers import load_waiver_file, apply_waivers_to_findings, generate_benchmark_yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger()
default_waiver_file = ".dsoinabox_waivers.yaml"

def build_parser() -> argparse.ArgumentParser:
    """build top-level arg parser"""
    parser = argparse.ArgumentParser(
        prog="dsoinabox",
        description="dsoinabox app scaffold.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show the app version and exit.",
    )

    parser.add_argument(
        "--tool_versions",
        action="store_true",
        help="show tool versions and exit.",
    )

    # tool selection
    parser.add_argument(
        "--tools", "-t",
        dest="tools",
        action="store",
        default="all",
        help="tools to run. comma-separated list: trufflehog, opengrep, syft, grype, checkov. can also use categories: SAST, SBOM, SECRET, SCA, IAC. default is all",
    )

    parser.add_argument(
        "--report_directory",
        action="store",
        default=None,  # set based on docker detection
        help="directory to store reports. default is 'reports' (relative to source). if running in docker and '/reports' mount exists, copies reports there",
    )

    # trufflehog
    parser.add_argument(
        "--trufflehog_help",
        action="store_true",
        help="show trufflehog help and exit",
    )

    parser.add_argument(
        "--trufflehog_args",
        action="store",
        help="extra args to pass to trufflehog",
    )

    # opengrep
    parser.add_argument(
        "--opengrep_help",
        action="store_true",
        help="show opengrep help and exit",
    )

    parser.add_argument(
        "--opengrep_args",
        action="store",
        help="extra args to pass to opengrep",
    )

    # syft
    parser.add_argument(
        "--syft_help",
        action="store_true",
        help="show syft help and exit",
    )

    parser.add_argument(
        "--syft_args",
        action="store",
        help="extra args to pass to syft",
    )

    # grype
    parser.add_argument(
        "--grype_help",
        action="store_true",
        help="show grype help and exit",
    )

    parser.add_argument(
        "--grype_args",
        action="store",
        help="extra args to pass to grype",
    )

    # checkov
    parser.add_argument(
        "--checkov_help",
        action="store_true",
        help="show checkov help and exit",
    )

    parser.add_argument(
        "--checkov_args",
        action="store",
        help="extra args to pass to checkov",
    )



    parser.add_argument(
        "--source",
        action="store",
        default=None,  # set based on docker detection
        help="path to code to scan. default is '/scan_target' in docker, current directory ('.') when run directly",
    )

    parser.add_argument(
        "--project_id",
        action="store",
        default=None,
        help="explicit project identifier (required for non-git directories). "
             "if not provided, will be derived from git remote or initial commit.",
    )

    # failure threshold for scan
    # should be one of: "none" or "info", "low", "medium", "high", "critical"
    '''
    opengrep severities:
        new rules: Low, Medium, High, Critical
        old rules: Error=High, Warning=Medium, Info=Low
    '''
    parser.add_argument(
        "--failure_threshold",
        action="store",
        default="none",
        help="failure threshold for the scan. should be one of: none, info, low, medium, high, critical. returns non-zero exit code if findings at or above this severity.",
    )

    #fail on secrets if found
    parser.add_argument(
        "--fail_on_secrets",
        action="store_true",
        help="fail the scan if any secrets are found.",
    )

    def str_to_bool(v):
        if isinstance(v, bool):
            return v
        if v is None:
            return True  # flag present without value, default True
        if isinstance(v, str):
            if v.lower() in ('yes', 'true', 't', 'y', '1'):
                return True
            elif v.lower() in ('no', 'false', 'f', 'n', '0'):
                return False
        raise argparse.ArgumentTypeError('Boolean value expected.')

    parser.add_argument(
        "--show_findings",
        type=str_to_bool,
        default=True,
        nargs='?',
        const=True,
        help="show findings from tools in cli. default is True. use --show_findings False to disable.",
    )

    
    parser.add_argument(
        "--waiver_file",
        action="store",
        default=default_waiver_file,
        help="path to waiver file (YAML format). if provided, findings matching waiver fingerprints will be marked as waived.",
    )

    parser.add_argument(
        "--output", "-o",
        action="store",
        default="html",
        help="output format(s) for the report. comma-separated list of formats: html, jenkins_html, json, sarif. default is html. example: --output json,html,sarif",
    )

    parser.add_argument(
        "--tool_output",
        action="store_true",
        default=False,
        help="if True, keep tool output files in tools_output subdirectory. default is False (tool outputs are deleted after report generation).",
    )

    parser.add_argument(
        "--benchmark",
        action="store_true",
        default=False,
        help="if True, generate benchmark.yaml file with all findings from all tools. benchmark entries will have type 'benchmark'.",
    )

    return parser

def prep_env(args: argparse.Namespace):
    """create reports directory if it doesn't exist"""
    os.makedirs(args.report_directory, exist_ok=True)
    
    # create tools_output directory for tool output files
    tools_output_dir = os.path.join(args.report_directory, "tools_output")
    os.makedirs(tools_output_dir, exist_ok=True)




def main(argv: list[str] | None = None) -> int:
    """app entrypoint. Returns exit code instead of calling sys.exit().
    
    Args:
        argv: Command-line arguments. If None, uses sys.argv[1:]
        
    Returns:
        Exit code: 0 for success, non-zero for failure
    """
    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        #no args provided, show help and exit
        parser.print_help()
        return 0

    #parse args
    args = parser.parse_args(argv)

    # Detect Docker environment and set defaults
    in_docker = is_running_in_docker()
    if in_docker:
        logger.debug("Detected Docker environment")
    else:
        logger.debug("Running outside Docker container")
    
    # Set default source path based on environment
    if args.source is None:
        args.source = "/scan_target" if in_docker else "."
        logger.info(f"Using default source path: {args.source}")
    
    # Set default report directory based on environment
    if args.report_directory is None:
        args.report_directory = "reports"
        logger.info(f"Using default report directory: {args.report_directory}")

    # Make report_directory relative to current working directory (pwd) if it's a relative path
    # This ensures reports are created relative to where the user invoked dsoinabox, not relative to source
    if not os.path.isabs(args.report_directory):
        args.report_directory = os.path.join(os.getcwd(), args.report_directory)
    
    # Create timestamp early - this will be used for the timestamped subdirectory
    # This eliminates the need for cleanup since each run gets its own timestamped directory
    timestamp = utcnow().strftime('%Y_%m_%dT%H_%M_%S')
    
    # Create timestamped subdirectory within the base report directory
    # This ensures each run has its own isolated directory, preventing conflicts in Jenkins pipelines
    timestamped_report_dir = os.path.join(args.report_directory, f"dsoinabox_{timestamp}")
    args.report_directory = timestamped_report_dir
    logger.info(f"Using timestamped report directory: {args.report_directory}")

    #trufflehog help
    if args.trufflehog_help:
        try:
            trufflehog_show_help()
        except ScannerError as e:
            logger.error(f"TruffleHog help failed: {e}")
            return 1
        return 0
    
    #opengrep help
    if args.opengrep_help:
        try:
            opengrep_show_help()
        except ScannerError as e:
            logger.error(f"OpenGrep help failed: {e}")
            return 1
        return 0
    
    #syft help
    if args.syft_help:
        try:
            syft_show_help()
        except ScannerError as e:
            logger.error(f"Syft help failed: {e}")
            return 1
        return 0
    
    #grype help
    if args.grype_help:
        try:
            grype_show_help()
        except ScannerError as e:
            logger.error(f"Grype help failed: {e}")
            return 1
        return 0
    
    #checkov help
    if args.checkov_help:
        try:
            checkov_show_help()
        except ScannerError as e:
            logger.error(f"Checkov help failed: {e}")
            return 1
        return 0


    if not os.path.exists(args.source):
        logger.error(f"Source code path {args.source} does not exist.")
        return 1

    # check if source is a git repository
    if is_git(args.source):
        is_git_repo = True
        logger.info(f"Source is a git repository: {args.source}")
    else:
        is_git_repo = False
        logger.info(f"Source is not a git repository: {args.source}")

    if args.tool_versions:
        invoked_pkg = __package__ or (sys.modules[__name__].__spec__.name if sys.modules[__name__].__spec__ else None)
        print(f"{invoked_pkg} {__version__}")
        try:
            syft_show_version()
            grype_show_version()
            trufflehog_show_version()
            opengrep_show_version()
            checkov_show_version()
        except ScannerError as e:
            logger.error(f"Version check failed: {e}")
            return 1
        return 0

    prep_env(args)
    set_git_safe_directory(args.source)

    #derive project_id
    try:
        project_id = derive_project_id(args.source, args.project_id)
        logger.info(f"Using project ID: {project_id}")
    except ValueError as e:
        logger.error(str(e))
        return 1
    
    #load waiver file if provided
    waiver_data = None
    if args.waiver_file:
        try:
            logger.info(f"Loading waiver file: {args.waiver_file}")
            waiver_data = load_waiver_file(os.path.join(args.source, args.waiver_file))
            logger.info(f"Waiver file loaded successfully. Found {len(waiver_data.get('finding_waivers', []))} finding waivers and {len(waiver_data.get('benchmark', []))} benchmark waivers.")
        except FileNotFoundError:
            logger.info(f"Did not find waiver file: {args.waiver_file}")
            if args.waiver_file != default_waiver_file:
                logger.error(f"Failed to load the specified waiver file: {args.waiver_file}.")
                return 1
        except Exception as e:
            logger.info(f"An error occurred while loading the waiver file: {e}")
            return 1
    
    #normalize failure threshold
    if args.failure_threshold and args.failure_threshold.lower() == "none":
        args.failure_threshold = None
    
    #normalize tools to set for lookup
    tools_set = {tool.strip().lower() for tool in args.tools.split(",")}
    all_tools = "all" in tools_set
    
    #helper to check if tool should run
    def should_run_tool(tool_names: list[str]) -> bool:
        """check if any tool name matches selected tools."""
        return all_tools or any(name in tools_set for name in tool_names)
    
    # Map tool categories/names to executable names
    tool_executables = {
        "trufflehog": "trufflehog",
        "opengrep": "opengrep",
        "syft": "syft",
        "grype": "grype",
        "checkov": "checkov",
    }
    
    # Check tool availability for requested tools
    missing_tools = []
    tools_to_check = []
    if should_run_tool(["trufflehog", "secret", "secrets"]):
        tools_to_check.append("trufflehog")
    if should_run_tool(["opengrep", "sast"]):
        tools_to_check.append("opengrep")
    if should_run_tool(["syft", "sbom"]):
        tools_to_check.append("syft")
    if should_run_tool(["grype", "sca"]):
        tools_to_check.append("grype")
    if should_run_tool(["checkov", "iac"]):
        tools_to_check.append("checkov")
    
    for tool in tools_to_check:
        if not check_tool_available(tool_executables[tool]):
            missing_tools.append(tool_executables[tool])
    
    if missing_tools:
        logger.error(
            f"The following required tools are not available in PATH: {', '.join(missing_tools)}. "
            f"Please ensure these tools are installed and available in your PATH."
        )
        return 1

    # Create tools_output directory path
    tools_output_dir = os.path.join(args.report_directory, "tools_output")
    
    #helper functions for parallel execution
    def run_trufflehog_workflow():
        """run trufflehog scan and processing."""
        logger.info(f"Running Trufflehog scan on {args.source}")
        scan_start = time.perf_counter()
        data = trufflehog_run_scan(args.source, args.trufflehog_args, tools_output_dir, git_repo=is_git_repo)
        scan_duration = time.perf_counter() - scan_start
        logger.info(f"Trufflehog scan completed in {scan_duration:.2f} seconds")
        tp = TrufflehogParser(report_directory=tools_output_dir, report_filename="trufflehog.json", data=data)
        logger.info(f"Processing Trufflehog findings")
        processing_start = time.perf_counter()
        tp.fingerprint_findings(args.source, project_id=project_id)
        #apply waiver checking
        if waiver_data:
            logger.info(f"Applying waiver checking to Trufflehog findings")
            apply_waivers_to_findings(tp.data, waiver_data)
        if args.show_findings:
            tp.cli_display_findings()
        processing_duration = time.perf_counter() - processing_start
        logger.info(f"Trufflehog findings processed in {processing_duration:.2f} seconds")
        return tp.data

    def run_opengrep_workflow():
        """run opengrep scan and processing."""
        logger.info(f"Running OpenGrep scan on {args.source}")
        scan_start = time.perf_counter()
        data = opengrep_run_scan(args.source, args.opengrep_args, tools_output_dir)
        scan_duration = time.perf_counter() - scan_start
        logger.info(f"OpenGrep scan completed in {scan_duration:.2f} seconds")
        ogp = OpengrepParser(report_directory=tools_output_dir, report_filename="opengrep.json", data=data)
        logger.info(f"Processing OpenGrep findings")
        processing_start = time.perf_counter()
        ogp.apply_threshold(args.failure_threshold)
        ogp.fingerprint_findings(args.source, project_id=project_id)
        #apply waiver checking
        if waiver_data:
            logger.info(f"Applying waiver checking to OpenGrep findings")
            apply_waivers_to_findings(ogp.data, waiver_data, findings_key="results", persist_waived_findings=False)
        if args.show_findings:
            ogp.cli_display_findings()
        processing_duration = time.perf_counter() - processing_start
        logger.info(f"OpenGrep findings processed in {processing_duration:.2f} seconds")
        return ogp.data

    def run_syft_workflow():
        """run syft scan."""
        logger.info(f"Running Syft scan on {args.source}")
        scan_start = time.perf_counter()
        data = syft_dir_scan(args.source, args.syft_args, tools_output_dir)
        scan_duration = time.perf_counter() - scan_start
        logger.info(f"Syft scan completed in {scan_duration:.2f} seconds")
        #syft doesn't need fingerprints or waiver checking
        return data

    def run_grype_workflow():
        """run grype scan and processing."""
        logger.info(f"Running Grype scan on {args.source}")
        scan_start = time.perf_counter()
        data = grype_run_scan(args.source, args.grype_args, tools_output_dir)
        scan_duration = time.perf_counter() - scan_start
        logger.info(f"Grype scan completed in {scan_duration:.2f} seconds")
        gp = GrypeParser(report_directory=tools_output_dir, report_filename="grype.json", data=data)
        logger.info(f"Processing Grype findings")
        processing_start = time.perf_counter()
        gp.apply_threshold(args.failure_threshold)
        gp.fingerprint_findings(project_id=project_id)
        #apply waiver checking
        if waiver_data:
            logger.info(f"Applying waiver checking to Grype findings")
            apply_waivers_to_findings(gp.data, waiver_data, findings_key="matches")
        if args.show_findings:
            gp.cli_display_findings()
        processing_duration = time.perf_counter() - processing_start
        logger.info(f"Grype findings processed in {processing_duration:.2f} seconds")
        return gp.data

    def run_checkov_workflow():
        """run checkov scan and processing."""
        logger.info(f"Running Checkov scan on {args.source}")
        scan_start = time.perf_counter()
        data = checkov_run_scan(args.source, args.checkov_args, tools_output_dir)
        scan_duration = time.perf_counter() - scan_start
        logger.info(f"Checkov scan completed in {scan_duration:.2f} seconds")
        cp = CheckovParser(report_directory=tools_output_dir, report_filename="checkov.json", data=data)
        logger.info(f"Processing Checkov findings")
        processing_start = time.perf_counter()
        cp.apply_threshold(args.failure_threshold)
        cp.fingerprint_findings(args.source, project_id=project_id)
        #apply waiver checking
        if waiver_data:
            logger.info(f"Applying waiver checking to Checkov findings")
            # For SARIF format, we need to extract results from runs[0].results
            runs = cp.data.get("runs", [])
            if runs:
                results = runs[0].get("results", [])
                # Apply waivers to results list
                filtered_results = []
                for result in results:
                    finding_fingerprints = result.get("fingerprints", {})
                    if isinstance(finding_fingerprints, dict):
                        from .waivers.matcher import check_waiver
                        is_waived = check_waiver(finding_fingerprints, waiver_data)
                        if not is_waived:
                            filtered_results.append(result)
                    else:
                        filtered_results.append(result)
                runs[0]["results"] = filtered_results
        if args.show_findings:
            cp.cli_display_findings()
        processing_duration = time.perf_counter() - processing_start
        logger.info(f"Checkov findings processed in {processing_duration:.2f} seconds")
        return cp.data

    #run independent scans in parallel
    trufflehog_data, opengrep_data, syft_data, grype_data, checkov_data = None, None, None, None, None
    
    #get git repo info early (doesn't depend on scan results)
    # Contract: GitRepoInfo is optional - if source is not a git repo, continue without git info
    git_repo_info = None
    try:
        git_repo_info = GitRepoInfo(args.source)
    except ValueError:
        # Source directory is not a git repository - this is acceptable, continue without git info
        logger.debug(f"Source directory {args.source} is not a git repository, continuing without git info")
        pass
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        
        #submit independent scans
        if should_run_tool(["trufflehog", "secret", "secrets"]):
            futures["trufflehog"] = executor.submit(run_trufflehog_workflow)
        
        if should_run_tool(["opengrep", "sast"]):
            futures["opengrep"] = executor.submit(run_opengrep_workflow)
        
        if should_run_tool(["syft", "sbom"]):
            futures["syft"] = executor.submit(run_syft_workflow)
        
        if should_run_tool(["checkov", "iac"]):
            futures["checkov"] = executor.submit(run_checkov_workflow)
        
        #wait for syft to complete first (grype depends on it)
        if "syft" in futures:
            try:
                syft_data = futures["syft"].result()
            except ScannerError as e:
                logger.error(f"Scanner error running syft: {e}")
                return 1
            except Exception as e:
                logger.error(f"Error running syft: {e}")
                return 1
        
        #now run grype in thread pool (after syft completes)
        if should_run_tool(["grype", "sca"]):
            futures["grype"] = executor.submit(run_grype_workflow)
        
        #collect all remaining results
        for tool_name, future in futures.items():
            if tool_name == "syft":
                continue  #already collected
            try:
                result = future.result()
                if tool_name == "trufflehog":
                    trufflehog_data = result
                elif tool_name == "opengrep":
                    opengrep_data = result
                elif tool_name == "grype":
                    grype_data = result
                elif tool_name == "checkov":
                    checkov_data = result
            except ScannerError as e:
                logger.error(f"Scanner error running {tool_name}: {e}")
                return 1
            except Exception as e:
                logger.error(f"Error running {tool_name}: {e}")
                return 1

    #security gate - check thresholds
    threshold_exceeded = False
    if args.failure_threshold and args.failure_threshold != "none":
        logger.info(f"Applying failure threshold of {args.failure_threshold}")
        
        if opengrep_data and opengrep_data.get("results"):
            threshold_exceeded = True
            logger.warning(
                f"Found {len(opengrep_data['results'])} OpenGrep findings "
                f"that exceed the failure threshold of {args.failure_threshold}"
            )
        
        if grype_data and grype_data.get("matches"):
            threshold_exceeded = True
            logger.warning(
                f"Found {len(grype_data['matches'])} Grype findings "
                f"that exceed the failure threshold of {args.failure_threshold}"
            )
        
        if checkov_data:
            runs = checkov_data.get("runs", [])
            if runs:
                results = runs[0].get("results", [])
                if results:
                    threshold_exceeded = True
                    logger.warning(
                        f"Found {len(results)} Checkov findings "
                        f"that exceed the failure threshold of {args.failure_threshold}"
                    )
    
    if args.fail_on_secrets and trufflehog_data:
        threshold_exceeded = True
        logger.warning(f"Found {len(trufflehog_data)} Trufflehog findings (fail_on_secrets enabled)")

    # Generate benchmark.yaml if --benchmark flag is set
    if args.benchmark:
        logger.info("Generating benchmark.yaml file")
        benchmark_path = os.path.join(args.report_directory, "benchmark.yaml")
        try:
            generate_benchmark_yaml(
                trufflehog_data=trufflehog_data,
                opengrep_data=opengrep_data,
                grype_data=grype_data,
                checkov_data=checkov_data,
                output_path=benchmark_path
            )
            logger.info(f"Benchmark file generated: {benchmark_path}")
        except Exception as e:
            logger.error(f"Failed to generate benchmark.yaml: {e}")
            return 1
    
    # Parse output formats (comma-separated)
    output_formats = [fmt.strip().lower() for fmt in args.output.split(",")]
    # Validate output formats
    valid_formats = {"html", "jenkins_html", "json", "sarif"}
    for fmt in output_formats:
        if fmt not in valid_formats:
            logger.error(f"Invalid output format: {fmt}. Supported formats: {', '.join(sorted(valid_formats))}")
            return 1
    
    # Generate reports for each requested format
    for output_format in output_formats:
        report_builder(
            reports_directory=args.report_directory,
            output_dir=args.report_directory,
            timestamp=timestamp,
            git_repo_info=git_repo_info.as_dict() if git_repo_info else None,
            data=(trufflehog_data, opengrep_data, syft_data, grype_data, checkov_data),
            output_format=output_format,
            waiver_data=waiver_data
        )
    
    # Clean up tools_output directory if --tool_output is False
    if not args.tool_output:
        tools_output_dir = os.path.join(args.report_directory, "tools_output")
        if os.path.exists(tools_output_dir):
            shutil.rmtree(tools_output_dir)

    #if running in Docker and "/reports" mount exists, copy reports to timestamped directory
    # Note: args.report_directory is already a timestamped directory, so we copy it directly
    if in_docker and os.path.exists("/reports"):
        logger.info("Copying reports to /reports mount")
        # The report_directory is already timestamped, so copy it to /reports with the same name
        shutil.copytree(args.report_directory, os.path.join("/reports", os.path.basename(args.report_directory)))

    #security gate failure
    if threshold_exceeded:
        logger.error(
            "All scans completed successfully, but one or more thresholds were exceeded, "
            "so exiting with a non-zero exit code"
        )
        return 1
    
    logger.info("All scans completed successfully.")
    return 0

