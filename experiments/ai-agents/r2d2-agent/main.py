"""
AI Network Diagnostic Agent (R2D2)

An AI-powered assistant that can execute network diagnostic tools like ping, curl,
dig, and traceroute to help software engineers debug network issues.

Inspired by: https://fly.io/blog/everyone-write-an-agent/

Requirements:
    - OpenAI API key must be set in environment variable: OPENAI_API_KEY
    - Network diagnostic tools must be installed: ping, curl, dig, traceroute

Usage:
    export OPENAI_API_KEY='your-api-key-here'
    python main.py
"""

from openai import OpenAI
from typing import Dict, List, Any, Optional
import json
import subprocess
import re
import logging
import argparse
import cmd2
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='R2D2 - AI Network Diagnostic Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose (debug) logging'
    )
    return parser.parse_args()


# Configuration class
class Config:
    """Configuration settings for R2D2 agent."""

    # Context management
    MAX_CONTEXT_MESSAGES: int = 50  # Maximum number of messages to keep in context (excluding system message)

    # Tool timeouts (in seconds)
    PING_TIMEOUT: int = 30
    CURL_TIMEOUT: int = 60
    TRACEROUTE_TIMEOUT: int = 90
    DIG_TIMEOUT: int = 45

    # Threading
    MAX_CONCURRENT_TOOLS: int = 4  # Maximum concurrent tool executions

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # OpenAI settings
    MODEL: str = "gpt-5"
    SYSTEM_PROMPT: str = "you're R2D2. Your job is to help a network engineer. Provide correct answers and be funny (in a nerdy way). You have access to network tools that you can invoke from user's computer"


# Parse command-line arguments
args = parse_arguments()

# Configure logging based on arguments
log_level = logging.DEBUG if args.verbose else logging.INFO
logging.basicConfig(
    level=log_level,
    format=Config.LOG_FORMAT
)
logger = logging.getLogger(__name__)


# Custom exception classes
class NetworkDiagnosticError(Exception):
    """Base exception for network diagnostic operations."""
    pass


class ValidationError(NetworkDiagnosticError):
    """Raised when input validation fails."""
    pass


class ToolExecutionError(NetworkDiagnosticError):
    """Raised when a diagnostic tool execution fails."""
    pass


class ToolTimeoutError(NetworkDiagnosticError):
    """Raised when a diagnostic tool times out."""
    pass


# Input validation functions
def is_valid_hostname(hostname: str) -> bool:
    """
    Validate hostname according to RFC 1123.

    Args:
        hostname: The hostname to validate

    Returns:
        True if valid, False otherwise
    """
    if not hostname or len(hostname) > 253:
        return False

    # Remove trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    # Hostname pattern: alphanumeric and hyphens, dots separate labels
    # Each label must start/end with alphanumeric, can contain hyphens
    pattern = r'^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$'

    if not re.match(pattern, hostname):
        return False

    # Check each label
    labels = hostname.split('.')
    for label in labels:
        if len(label) > 63 or label.startswith('-') or label.endswith('-'):
            return False

    return True


def is_valid_url(url: str) -> bool:
    """
    Validate URL format.

    Args:
        url: The URL to validate

    Returns:
        True if valid, False otherwise
    """
    if not url or len(url) > 2048:  # Reasonable URL length limit
        return False

    try:
        result = urlparse(url)
        # Must have scheme and netloc
        return all([result.scheme in ['http', 'https', 'ftp'], result.netloc])
    except Exception:
        return False


def validate_host_input(host: str) -> str:
    """
    Validate and sanitize host input.

    Args:
        host: The hostname or IP to validate

    Returns:
        The validated host

    Raises:
        ValidationError: If host is invalid
    """
    if not host or not isinstance(host, str):
        raise ValidationError("Host must be a non-empty string")

    host = host.strip()

    # Check for shell metacharacters that could be dangerous
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    if any(char in host for char in dangerous_chars):
        raise ValidationError(f"Host contains invalid characters: {host}")

    # Validate as hostname or IP
    if not is_valid_hostname(host):
        raise ValidationError(f"Invalid hostname format: {host}")

    return host


def validate_url_input(url: str) -> str:
    """
    Validate and sanitize URL input.

    Args:
        url: The URL to validate

    Returns:
        The validated URL

    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")

    url = url.strip()

    if not is_valid_url(url) or is_valid_hostname(url):
        raise ValidationError(f"Invalid URL format: {url}")

    return url


tools = [
    {
        "type": "function", "name": "ping",
        "description": "ping some host on the internet",
        "parameters": {
            "type": "object", "properties": {
                "host": {
                    "type": "string", "description": "hostname or IP",
                },
            },
            "required": ["host"],
        },
    },
        {
        "type": "function", "name": "curl",
        "description": "curl - transfer a URL",
        "parameters": {
            "type": "object", "properties": {
                "host": {
                    "type": "string", "description": "hostname or IP",
                },
            },
            "required": ["host"],
        },
    },
    {
        "type": "function", "name": "dig",
        "description": "DNS lookup utility",
        "parameters": {
            "type": "object", "properties": {
                "host": {
                    "type": "string", "description": "hostname",
                },
            },
            "required": ["host"],
        },
    },
    {
        "type": "function", "name": "traceroute",
        "description": "traceroute to some host on the internet",
        "parameters": {
            "type": "object", "properties": {
                "host": {
                    "type": "string", "description": "hostname or IP",
                },
            },
            "required": ["host"],
        },
    },
]


def ping(host: str = "") -> str:
    """
    Execute ping command to test network connectivity.

    Args:
        host: Hostname or IP address to ping

    Returns:
        stdout from ping command or error message

    Raises:
        ToolTimeoutError: If ping times out after 30 seconds
    """
    logger.info(f"Attempting ping to {host}")
    try:
        # Validate input
        host = validate_host_input(host)

        result = subprocess.run(
            ["ping", "-c", "5", host],
            text=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            timeout=Config.PING_TIMEOUT)

        if result.returncode != 0:
            raise ToolExecutionError(f"ping command failed with return code {result.returncode}")

        logger.debug(f"Ping successful for {host}")
        return result.stdout
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        return f"Validation error: {e}"
    except subprocess.TimeoutExpired:
        error_msg = f"ping to {host} timed out after {Config.PING_TIMEOUT} seconds"
        logger.error(f"Timeout error: {error_msg}")
        raise ToolTimeoutError(error_msg)
    except ToolExecutionError as e:
        logger.error(f"Execution error: {e}")
        return f"Execution error: {e}"
    except Exception as e:
        logger.exception(f"Unexpected error while pinging host {host}: {e}")
        return f"Unexpected error: {e}"

def curl(host: str = "") -> str:
    """
    Execute curl command to fetch URL content.

    Args:
        host: URL to fetch (must be valid HTTP/HTTPS/FTP URL)

    Returns:
        stdout from curl command or error message

    Raises:
        ToolTimeoutError: If curl times out after 60 seconds
    """
    logger.info(f"Attempting curl to {host}")
    try:
        # Validate input - curl expects URLs
        host = validate_url_input(host)

        result = subprocess.run(
            ["curl",  host],
            text=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            timeout=Config.CURL_TIMEOUT)

        if result.returncode != 0:
            raise ToolExecutionError(f"curl command failed with return code {result.returncode}")

        logger.debug(f"Curl successful for {host}")
        return result.stdout
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        return f"Validation error: {e}"
    except subprocess.TimeoutExpired:
        error_msg = f"curl to {host} timed out after {Config.CURL_TIMEOUT} seconds"
        logger.error(f"Timeout error: {error_msg}")
        raise ToolTimeoutError(error_msg)
    except ToolExecutionError as e:
        logger.error(f"Execution error: {e}")
        return f"Execution error: {e}"
    except Exception as e:
        logger.exception(f"Unexpected error while executing curl to {host}: {e}")
        return f"Unexpected error: {e}"
    
def traceroute(host: str = "") -> str:
    """
    Execute traceroute command to trace network path to host.

    Args:
        host: Hostname or IP address to trace route to

    Returns:
        stdout from traceroute command or error message

    Raises:
        ToolTimeoutError: If traceroute times out after 90 seconds
    """
    logger.info(f"Attempting traceroute to {host}")
    try:
        # Validate input
        host = validate_host_input(host)

        result = subprocess.run(
            ["traceroute", "-I", host],
            text=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            timeout=Config.TRACEROUTE_TIMEOUT)

        if result.returncode != 0:
            raise ToolExecutionError(f"traceroute command failed with return code {result.returncode}")

        logger.debug(f"Traceroute successful for {host}")
        return result.stdout
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        return f"Validation error: {e}"
    except subprocess.TimeoutExpired:
        error_msg = f"traceroute to {host} timed out after {Config.TRACEROUTE_TIMEOUT} seconds"
        logger.error(f"Timeout error: {error_msg}")
        raise ToolTimeoutError(error_msg)
    except ToolExecutionError as e:
        logger.error(f"Execution error: {e}")
        return f"Execution error: {e}"
    except Exception as e:
        logger.exception(f"Unexpected error while executing traceroute to {host}: {e}")
        return f"Unexpected error: {e}"

def dig(host: str = "") -> str:
    """
    Execute dig command to perform DNS lookup.

    Args:
        host: Hostname to look up in DNS

    Returns:
        stdout from dig command or error message

    Raises:
        ToolTimeoutError: If dig times out after 45 seconds
    """
    logger.info(f"Attempting dig to {host}")
    try:
        # Validate input
        host = validate_host_input(host)

        result = subprocess.run(
            ["dig", "+trace", host],
            text=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            timeout=Config.DIG_TIMEOUT)

        if result.returncode != 0:
            raise ToolExecutionError(f"dig command failed with return code {result.returncode}")

        logger.debug(f"Dig successful for {host}")
        return result.stdout
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        return f"Validation error: {e}"
    except subprocess.TimeoutExpired:
        error_msg = f"dig to {host} timed out after {Config.DIG_TIMEOUT} seconds"
        logger.error(f"Timeout error: {error_msg}")
        raise ToolTimeoutError(error_msg)
    except ToolExecutionError as e:
        logger.error(f"Execution error: {e}")
        return f"Execution error: {e}"
    except Exception as e:
        logger.exception(f"Unexpected error while executing dig to {host}: {e}")
        return f"Unexpected error: {e}"

    
tool_registry = {
    "ping": ping,
    "traceroute": traceroute,
    "dig": dig,
    "curl": curl,
}


def manage_context_window() -> None:
    """
    Manage context window size to prevent unbounded growth.

    Keeps the system message and limits conversation history to MAX_CONTEXT_MESSAGES.
    Older messages are removed when the limit is exceeded.
    """
    global context

    if len(context) > Config.MAX_CONTEXT_MESSAGES + 1:  # +1 for system message
        # Keep system message (index 0) and last MAX_CONTEXT_MESSAGES messages
        context = [context[0]] + context[-(Config.MAX_CONTEXT_MESSAGES):]


client = OpenAI()
context = [{
    "role": "system", "content": Config.SYSTEM_PROMPT
}]


def call(tools: List[Dict[str, Any]]) -> Any:
    """Call OpenAI API with tools and context."""
    return client.responses.create(model=Config.MODEL, tools=tools, input=context)

def tool_call(item: Any) -> List[Any]:
    """
    Execute a single tool call.

    Args:
        item: Tool call item from OpenAI response

    Returns:
        List containing the original item and function call output
    """
    logger.info(f"Invoking {item.name} with args: {item.arguments}")
    if item.name not in tool_registry:
        logger.error(f"Unknown tool requested: {item.name}")
        return "Error"

    result = tool_registry[item.name](**json.loads(item.arguments))
    return [ item, {
        "type": "function_call_output",
        "call_id": item.call_id,
        "output": result
    }]

def handle_tools(tools: List[Dict[str, Any]], response: Any) -> bool:
    """
    Handle tool calls from OpenAI response.

    Executes multiple tool calls concurrently using threads for better performance.

    Args:
        tools: List of available tools
        response: OpenAI API response

    Returns:
        True if any tools were called, False otherwise
    """
    logger.debug(f"Handling tools. Response: {response.output}")
    if response.output[0].type == "reasoning":
        context.append(response.output[0])

    osz = len(context)

    # Collect all function call items
    function_calls = [item for item in response.output if item.type == "function_call"]

    if not function_calls:
        return len(context) != osz

    # Execute all tool calls concurrently
    if len(function_calls) == 1:
        # Single call - no need for threading overhead
        context.extend(tool_call(function_calls[0]))
    else:
        # Multiple calls - execute concurrently
        logger.info(f"Executing {len(function_calls)} tool calls concurrently")
        max_workers = min(len(function_calls), Config.MAX_CONCURRENT_TOOLS)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tool calls
            future_to_item = {executor.submit(tool_call, item): item for item in function_calls}

            # Collect results as they complete
            results = []
            for future in as_completed(future_to_item):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    item = future_to_item[future]
                    logger.exception(f"Tool call failed for {item.name}: {e}")
                    # Add error result to context
                    results.append([item, {
                        "type": "function_call_output",
                        "call_id": item.call_id,
                        "output": f"Error: {str(e)}"
                    }])

            # Extend context with all results
            for result in results:
                context.extend(result)

    return len(context) != osz

def process(line: str) -> str:
    """
    Process user input and get AI response.

    Args:
        line: User input text

    Returns:
        AI assistant response text
    """
    context.append({"role": "user", "content": line})
    manage_context_window()  # Manage context size
    response = call(tools)
    # new code: resolve tool calls
    while handle_tools(tools, response):
        response = call(tools)
    context.append({"role": "assistant", "content": response.output_text})
    manage_context_window()  # Manage context size after response
    return response.output_text


class R2D2Shell(cmd2.Cmd):
    """Interactive shell for R2D2 agent."""

    intro = "R2D2 Network Diagnostic Agent - Type 'help' or '?' for commands, 'quit' to exit"
    prompt = "R2D2> "

    def __init__(self, *args, **kwargs):
        """Initialize the shell."""
        super().__init__(*args, **kwargs)
        # Remove default cmd2 commands that aren't useful for our use case
        self.hidden_commands.extend(['alias', 'edit', 'macro', 'run_pyscript', 'run_script', 'shortcuts'])

    def default(self, statement: cmd2.Statement) -> None:
        """
        Handle all user input as AI queries.

        Args:
            statement: The parsed user input
        """
        line = statement.raw
        if not line.strip():
            return

        try:
            result = process(line)
            self.poutput(f"R2D2>; {result}\n")
        except Exception as e:
            logger.exception(f"Error processing query: {e}")
            self.perror(f"Error: {e}")

    def do_clear(self, _) -> None:
        """Clear the conversation context (start fresh)."""
        global context
        context = [{"role": "system", "content": Config.SYSTEM_PROMPT}]
        self.poutput("✓ Context cleared! Starting fresh conversation.")

    def do_stats(self, _) -> None:
        """Show statistics about the current conversation context."""
        self.poutput(f"Context Statistics:")
        self.poutput(f"  Messages in context: {len(context)}")
        self.poutput(f"  Max messages allowed: {Config.MAX_CONTEXT_MESSAGES}")
        self.poutput(f"  Context utilization: {len(context)-1}/{Config.MAX_CONTEXT_MESSAGES} ({(len(context)-1)/Config.MAX_CONTEXT_MESSAGES*100:.1f}%)")

    def do_config(self, _) -> None:
        """Show current configuration settings."""
        self.poutput("Configuration:")
        self.poutput(f"  Model: {Config.MODEL}")
        self.poutput(f"  Max context messages: {Config.MAX_CONTEXT_MESSAGES}")
        self.poutput(f"  Max concurrent tools: {Config.MAX_CONCURRENT_TOOLS}")
        self.poutput(f"\nTool Timeouts:")
        self.poutput(f"  Ping: {Config.PING_TIMEOUT}s")
        self.poutput(f"  Curl: {Config.CURL_TIMEOUT}s")
        self.poutput(f"  Traceroute: {Config.TRACEROUTE_TIMEOUT}s")
        self.poutput(f"  Dig: {Config.DIG_TIMEOUT}s")


def main() -> None:
    """Main entry point for R2D2 agent."""
    shell = R2D2Shell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, exiting...")
        print("\nGoodbye!")


if __name__ == '__main__':
    main()
