"""Axiom hook for distributed scanning.

This hook wraps tool commands with axiom-scan for distributed execution
across an Axiom fleet when the --axiom flag is passed.

Usage:
    secator task httpx urls.txt --axiom
    secator task nuclei urls.txt --axiom
"""

import os
import shlex
import shutil
from pathlib import Path

from secator.config import CONFIG
from secator.output_types import Info, Warning, Error
from secator.runners import Task
from secator.utils import debug


# Tools that support URL/target list input and work well with axiom-scan
AXIOM_SUPPORTED_TOOLS = [
    'httpx',
    'nuclei',
    'katana',
    'nmap',
    'naabu',
    'subfinder',
    'arjun',
    'gospider',
    'wafw00f',
    'dalfox',
    'dirsearch',
    'xurlfind3r',
    'urlfinder',
    'dnsx',
    'ffuf',
    'feroxbuster',
]


def is_axiom_installed():
    """Check if axiom-scan is installed on the system.
    
    Returns:
        bool: True if axiom-scan binary is found in PATH.
    """
    return shutil.which('axiom-scan') is not None


def is_axiom_enabled(self):
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


def get_axiom_module_name(tool_name):
    """Map secator tool name to axiom module name.
    
    Some tools may have different module names in axiom.
    
    Args:
        tool_name (str): Secator tool name.
        
    Returns:
        str: Axiom module name.
    """
    # Module name mappings (if different from tool name)
    module_map = {
        # Most tools have the same name
        # Add custom mappings here if needed
    }
    return module_map.get(tool_name, tool_name)


def build_axiom_command(self, original_cmd, tool_name, inputs_path):
    """Build axiom-scan command from original command.
    
    Args:
        self: Command instance.
        original_cmd (str): Original tool command.
        tool_name (str): Name of the tool.
        inputs_path (str): Path to input file.
        
    Returns:
        str: axiom-scan command.
    """
    module_name = get_axiom_module_name(tool_name)
    
    # Get axiom config
    fleet_name = CONFIG.addons.axiom.fleet_name
    output_dir = CONFIG.addons.axiom.output_dir
    
    # Create output directory if needed
    os.makedirs(output_dir, exist_ok=True)
    
    # Build output path
    output_path = f"{output_dir}/{self.unique_name}_output.txt"
    
    # Parse original command to extract tool arguments
    # Remove the input file/flag from the original command
    cmd_parts = shlex.split(original_cmd)
    
    # Find and remove input-related arguments
    tool_args = []
    skip_next = False
    input_flags = ['-l', '-list', '-u', '-iL', '-dL', '-i', '-S', '-f', '-cl', 'file', '-domain']
    
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
    print(f"[AXIOM DEBUG] Hook called for tool: {getattr(self, 'cmd_name', 'unknown')}")
    print(f"[AXIOM DEBUG] run_opts.axiom: {self.run_opts.get('axiom', False)}")
    print(f"[AXIOM DEBUG] inputs_path: {getattr(self, 'inputs_path', None)}")
    
    # Check if axiom is enabled
    if not is_axiom_enabled(self):
        print("[AXIOM DEBUG] axiom not enabled, skipping")
        debug('axiom not enabled, skipping', sub='hooks.axiom')
        return
    
    # Check if axiom-scan is installed
    if not is_axiom_installed():
        print("[AXIOM DEBUG] axiom-scan not installed, aborting")
        self._print('[bold red]Error: axiom-scan is not installed. Please install Axiom first: https://github.com/pry0cc/axiom[/]', rich=True)
        debug('axiom-scan not installed, aborting', sub='hooks.axiom')
        raise SystemExit(1)
    
    # Check if tool is supported
    tool_name = self.cmd_name
    if tool_name not in AXIOM_SUPPORTED_TOOLS:
        print(f"[AXIOM DEBUG] tool {tool_name} not in AXIOM_SUPPORTED_TOOLS, skipping")
        debug(f'tool {tool_name} not in AXIOM_SUPPORTED_TOOLS, skipping', sub='hooks.axiom')
        return
    
    # Check if we have a file input (multiple targets)
    if not self.inputs_path:
        print("[AXIOM DEBUG] no file input (inputs_path is None), skipping axiom")
        debug('no file input (inputs_path is None), skipping axiom', sub='hooks.axiom')
        return
    
    # Build axiom command
    original_cmd = self.cmd
    print(f"[AXIOM DEBUG] Original cmd: {original_cmd}")
    axiom_cmd = build_axiom_command(self, original_cmd, tool_name, self.inputs_path)
    print(f"[AXIOM DEBUG] Axiom cmd: {axiom_cmd}")
    
    # Replace command
    debug(f'original cmd: {original_cmd}', sub='hooks.axiom')
    debug(f'axiom cmd: {axiom_cmd}', sub='hooks.axiom')
    
    self.cmd = axiom_cmd
    self.shell = False  # axiom-scan should not run in shell mode
    
    # Log info about axiom usage
    self._print(f'[bold cyan]:rocket: Using axiom-scan for distributed scanning[/]', rich=True)


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
    # This allows the normal item_loader to process the results
    try:
        with open(output_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    # Process line through normal item loaders
                    yield from self.process_line(line)
    except Exception as e:
        debug(f'error reading axiom output: {e}', sub='hooks.axiom')


# Register hooks with Task runner
HOOKS = {
    Task: {
        'on_cmd': [modify_cmd_for_axiom],
        'on_cmd_done': [on_axiom_end]
    }
}

