"""Axiom hook for distributed scanning.

This hook wraps tool commands with axiom-scan for distributed execution
across an Axiom fleet when the --axiom flag is passed.

Usage:
    secator task httpx urls.txt --axiom
    secator task nuclei urls.txt --axiom
    
Configuration:
    secator config set addons.axiom.enabled true
    secator config set addons.axiom.fleet_name myfleet
"""

import os
import shlex
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from secator.config import CONFIG
from secator.output_types import Info, Warning, Error
from secator.runners import Task
from secator.utils import debug


# ============================================================================
# AXIOM TOOL CONFIGURATIONS
# ============================================================================

# Each tool config contains:
#   - module: axiom module name (if different from tool name)
#   - input_types: types of input the tool accepts
#   - file_flag: flag used for file input in original tool
#   - supports_json: whether tool supports JSON output
#   - category: tool category for grouping

AXIOM_TOOL_CONFIGS: Dict[str, Dict] = {
    # HTTP Probing & Analysis
    'httpx': {
        'module': 'httpx',
        'input_types': ['host', 'host:port', 'ip', 'url'],
        'file_flag': '-l',
        'supports_json': True,
        'category': 'http',
        'description': 'Fast HTTP toolkit for probing',
    },
    'katana': {
        'module': 'katana',
        'input_types': ['url'],
        'file_flag': '-list',
        'supports_json': True,
        'category': 'http',
        'description': 'Web crawler',
    },
    'gospider': {
        'module': 'gospider',
        'input_types': ['url'],
        'file_flag': '-S',
        'supports_json': True,
        'category': 'http',
        'description': 'Web spider',
    },
    'wafw00f': {
        'module': 'wafw00f',
        'input_types': ['url'],
        'file_flag': '-i',
        'supports_json': True,
        'category': 'http',
        'description': 'WAF detection',
    },
    
    # Fuzzing & Discovery
    'dirsearch': {
        'module': 'dirsearch',
        'input_types': ['url'],
        'file_flag': '-l',
        'supports_json': True,
        'category': 'fuzzing',
        'description': 'Directory brute-forcer',
    },
    'ffuf': {
        'module': 'ffuf',
        'input_types': ['url'],
        'file_flag': None,  # Does not support file list natively
        'supports_json': True,
        'category': 'fuzzing',
        'description': 'Fast web fuzzer',
    },
    'feroxbuster': {
        'module': 'feroxbuster',
        'input_types': ['url'],
        'file_flag': None,  # Uses stdin
        'supports_json': True,
        'category': 'fuzzing',
        'description': 'Content discovery',
    },
    'arjun': {
        'module': 'arjun',
        'input_types': ['url'],
        'file_flag': '-i',
        'supports_json': True,
        'category': 'fuzzing',
        'description': 'Parameter discovery',
    },
    
    # Vulnerability Scanning
    'nuclei': {
        'module': 'nuclei',
        'input_types': ['host', 'ip', 'url'],
        'file_flag': '-l',
        'supports_json': True,
        'category': 'vuln',
        'description': 'Vulnerability scanner',
    },
    'dalfox': {
        'module': 'dalfox',
        'input_types': ['url'],
        'file_flag': 'file',
        'supports_json': True,
        'category': 'vuln',
        'description': 'XSS scanner',
    },
    
    # Port Scanning & Network
    'nmap': {
        'module': 'nmap',
        'input_types': ['host', 'ip'],
        'file_flag': '-iL',
        'supports_json': False,  # XML output
        'category': 'network',
        'description': 'Port scanner',
    },
    'naabu': {
        'module': 'naabu',
        'input_types': ['host', 'ip'],
        'file_flag': '-list',
        'supports_json': True,
        'category': 'network',
        'description': 'Fast port scanner',
    },
    'fping': {
        'module': 'fping',
        'input_types': ['ip', 'host'],
        'file_flag': '-f',
        'supports_json': False,
        'category': 'network',
        'description': 'Ping sweep',
    },
    'mapcidr': {
        'module': 'mapcidr',
        'input_types': ['cidr_range', 'ip'],
        'file_flag': '-cl',
        'supports_json': False,
        'category': 'network',
        'description': 'CIDR manipulation',
    },
    
    # DNS & Subdomain
    'subfinder': {
        'module': 'subfinder',
        'input_types': ['host'],
        'file_flag': '-dL',
        'supports_json': True,
        'category': 'recon',
        'description': 'Subdomain discovery',
    },
    'dnsx': {
        'module': 'dnsx',
        'input_types': ['host', 'cidr_range', 'ip'],
        'file_flag': '-d',  # Dynamic
        'supports_json': True,
        'category': 'recon',
        'description': 'DNS toolkit',
    },
    'urlfinder': {
        'module': 'urlfinder',
        'input_types': ['host', 'url'],
        'file_flag': '-list',
        'supports_json': True,
        'category': 'recon',
        'description': 'URL discovery',
    },
    'xurlfind3r': {
        'module': 'xurlfind3r',
        'input_types': ['host', 'url'],
        'file_flag': '-l',
        'supports_json': True,
        'category': 'recon',
        'description': 'URL finder',
    },
    'gau': {
        'module': 'gau',
        'input_types': ['url', 'host'],
        'file_flag': None,  # Uses stdin
        'supports_json': True,
        'category': 'recon',
        'description': 'Get All URLs',
    },
    
    # SSL/TLS
    'testssl': {
        'module': 'testssl.sh',
        'input_types': ['host'],
        'file_flag': '-iL',
        'supports_json': True,
        'category': 'ssl',
        'description': 'SSL/TLS testing',
    },
    'sshaudit': {
        'module': 'ssh-audit',
        'input_types': ['host', 'ip'],
        'file_flag': '-T',
        'supports_json': True,
        'category': 'ssl',
        'description': 'SSH audit',
    },
    
    # WordPress
    'wpprobe': {
        'module': 'wpprobe',
        'input_types': ['url'],
        'file_flag': '-f',
        'supports_json': True,
        'category': 'cms',
        'description': 'WordPress probe',
    },
    
    # Parameter Tools
    'x8': {
        'module': 'x8',
        'input_types': ['url'],
        'file_flag': '-u',
        'supports_json': True,
        'category': 'fuzzing',
        'description': 'Hidden parameters discovery',
    },
}

# Simple list for backward compatibility
AXIOM_SUPPORTED_TOOLS = list(AXIOM_TOOL_CONFIGS.keys())


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def is_axiom_installed() -> bool:
    """Check if axiom-scan is installed on the system.
    
    Returns:
        bool: True if axiom-scan binary is found in PATH.
    """
    return shutil.which('axiom-scan') is not None


def is_axiom_enabled(self) -> bool:
    """Check if axiom is enabled for this command.
    
    Args:
        self: Command instance.
        
    Returns:
        bool: True if axiom should be used.
    """
    # Check if --axiom flag was passed
    axiom_flag = self.run_opts.get('axiom', False)
    
    # Also check config for global enablement
    config_enabled = CONFIG.addons.axiom.enabled
    
    return axiom_flag or config_enabled


def get_axiom_tool_config(tool_name: str) -> Optional[Dict]:
    """Get axiom configuration for a tool.
    
    Args:
        tool_name: Name of the tool.
        
    Returns:
        Dict or None: Tool configuration if supported.
    """
    return AXIOM_TOOL_CONFIGS.get(tool_name)


def get_axiom_module_name(tool_name: str) -> str:
    """Map secator tool name to axiom module name.
    
    Args:
        tool_name: Secator tool name.
        
    Returns:
        str: Axiom module name.
    """
    config = get_axiom_tool_config(tool_name)
    if config:
        return config.get('module', tool_name)
    return tool_name


def list_axiom_tools(category: Optional[str] = None) -> List[Dict]:
    """List all axiom-supported tools.
    
    Args:
        category: Optional category filter.
        
    Returns:
        List of tool info dicts.
    """
    tools = []
    for name, config in AXIOM_TOOL_CONFIGS.items():
        if category and config.get('category') != category:
            continue
        tools.append({
            'name': name,
            'module': config.get('module', name),
            'category': config.get('category', 'other'),
            'description': config.get('description', ''),
            'input_types': config.get('input_types', []),
            'supports_json': config.get('supports_json', False),
        })
    return sorted(tools, key=lambda x: (x['category'], x['name']))


def get_axiom_categories() -> List[str]:
    """Get list of tool categories.
    
    Returns:
        List of category names.
    """
    categories = set()
    for config in AXIOM_TOOL_CONFIGS.values():
        categories.add(config.get('category', 'other'))
    return sorted(categories)


def print_axiom_tools_table():
    """Print a formatted table of axiom-supported tools."""
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    
    table = Table(title="Axiom Supported Tools", show_header=True)
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Input Types", style="green")
    table.add_column("JSON", style="yellow")
    table.add_column("Description")
    
    for tool in list_axiom_tools():
        table.add_row(
            tool['name'],
            tool['category'],
            ', '.join(tool['input_types']),
            '✓' if tool['supports_json'] else '✗',
            tool['description']
        )
    
    console.print(table)


# ============================================================================
# AXIOM COMMAND BUILDER
# ============================================================================

def build_axiom_command(self, original_cmd: str, tool_name: str, inputs_path: str) -> str:
    """Build axiom-scan command from original command.
    
    Args:
        self: Command instance.
        original_cmd: Original tool command.
        tool_name: Name of the tool.
        inputs_path: Path to input file.
        
    Returns:
        str: axiom-scan command.
    """
    tool_config = get_axiom_tool_config(tool_name)
    module_name = get_axiom_module_name(tool_name)
    
    # Get axiom config
    fleet_name = CONFIG.addons.axiom.fleet_name
    output_dir = CONFIG.addons.axiom.output_dir
    
    # Create output directory if needed
    os.makedirs(output_dir, exist_ok=True)
    
    # Build output path
    output_path = f"{output_dir}/{self.unique_name}_output.txt"
    
    # Parse original command to extract tool arguments
    cmd_parts = shlex.split(original_cmd)
    
    # Get file_flag for this tool
    file_flag = tool_config.get('file_flag') if tool_config else '-l'
    
    # Find and remove input-related arguments
    tool_args = []
    skip_next = False
    input_flags = ['-l', '-list', '-u', '-iL', '-dL', '-i', '-S', '-f', '-cl', 'file', '-domain', '-d', '-host', '-t', '-T', '--url']
    
    for i, part in enumerate(cmd_parts):
        if skip_next:
            skip_next = False
            continue
        
        # Skip the tool name itself (first part)
        if i == 0:
            continue
            
        # Skip input flags and their values
        if part in input_flags:
            skip_next = True
            continue
        
        # Skip if this looks like it's the input file itself
        if inputs_path and part == inputs_path:
            continue
            
        tool_args.append(part)
    
    # Build axiom-scan command
    # Format: axiom-scan <input_file> -m <module> [module_args] -o <output>
    axiom_cmd = f"axiom-scan {shlex.quote(inputs_path)} -m {module_name}"
    
    # Add fleet name if specified
    if fleet_name:
        axiom_cmd += f" --fleet {shlex.quote(fleet_name)}"
    
    # Add tool arguments
    if tool_args:
        axiom_cmd += " " + " ".join(tool_args)
    
    # Add output file
    axiom_cmd += f" -o {shlex.quote(output_path)}"
    
    # Store output path for later use
    self._axiom_output_path = output_path
    
    return axiom_cmd


# ============================================================================
# HOOK FUNCTIONS
# ============================================================================

def modify_cmd_for_axiom(self):
    """Wrap command with axiom-scan for distributed scanning.
    
    This hook is called during command initialization (on_cmd hook).
    It modifies the command to use axiom-scan if:
    1. The --axiom flag is passed or addons.axiom.enabled is True
    2. axiom-scan is installed on the system
    3. The tool is in the AXIOM_SUPPORTED_TOOLS list
    4. There are multiple inputs (using file input)
    
    Args:
        self: Command instance.
    """
    # Check if axiom is enabled
    if not is_axiom_enabled(self):
        debug('axiom not enabled, skipping', sub='hooks.axiom')
        return
    
    # Check if axiom-scan is installed
    if not is_axiom_installed():
        self._print('[bold red]Error: axiom-scan is not installed. Please install Axiom first: https://github.com/pry0cc/axiom[/]', rich=True)
        debug('axiom-scan not installed, aborting', sub='hooks.axiom')
        raise SystemExit(1)
    
    # Check if tool is supported
    tool_name = self.cmd_name
    if tool_name not in AXIOM_SUPPORTED_TOOLS:
        debug(f'tool {tool_name} not in AXIOM_SUPPORTED_TOOLS, skipping', sub='hooks.axiom')
        return
    
    # Check if we have a file input (multiple targets)
    if not self.inputs_path:
        debug('no file input (inputs_path is None), skipping axiom', sub='hooks.axiom')
        return
    
    # Get tool config for info
    tool_config = get_axiom_tool_config(tool_name)
    
    # Build axiom command
    original_cmd = self.cmd
    axiom_cmd = build_axiom_command(self, original_cmd, tool_name, self.inputs_path)
    
    # Replace command
    debug(f'original cmd: {original_cmd}', sub='hooks.axiom')
    debug(f'axiom cmd: {axiom_cmd}', sub='hooks.axiom')
    
    self.cmd = axiom_cmd
    self.shell = False  # axiom-scan should not run in shell mode
    
    # Log info about axiom usage
    category = tool_config.get('category', 'unknown') if tool_config else 'unknown'
    self._print(f'[bold cyan]:rocket: Using axiom-scan for distributed scanning ({category})[/]', rich=True)


def on_axiom_end(self):
    """Handle axiom output after command completes.
    
    This hook reads the axiom output file and processes results.
    
    Args:
        self: Command instance.
    """
    # Check if we used axiom
    output_path = getattr(self, '_axiom_output_path', None)
    if not output_path:
        return
    
    # Check if output file exists
    if not Path(output_path).exists():
        debug(f'axiom output file not found: {output_path}', sub='hooks.axiom')
        return
    
    debug(f'processing axiom output from: {output_path}', sub='hooks.axiom')
    
    # Read and yield lines from output file
    try:
        with open(output_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    yield from self.process_line(line)
    except Exception as e:
        debug(f'error reading axiom output: {e}', sub='hooks.axiom')


# ============================================================================
# HOOK REGISTRATION
# ============================================================================

HOOKS = {
    Task: {
        'on_cmd': [modify_cmd_for_axiom],
        'on_cmd_done': [on_axiom_end]
    }
}
