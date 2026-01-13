# R2D2 - AI Network Diagnostic Agent

An AI-powered assistant that executes network diagnostic tools to help software engineers debug network issues.

Inspired by: https://fly.io/blog/everyone-write-an-agent/

## Features

- AI-powered conversational interface using [aisuite](https://github.com/andrewyng/aisuite) (supports OpenAI, Anthropic, Google, AWS Bedrock, and more)
- **7 network diagnostic commands**: `ping`, `curl`, `dig`, `traceroute`, `whois`, `netstat`, `nc`
- **Privileged tool** (requires sudo): `mtr` - advanced traceroute with statistics
- **Concurrent tool execution** using threads for better performance
- Comprehensive input validation (RFC 1123 hostname validation, URL validation, port validation)
- Command injection prevention
- Configurable timeouts for all tools
- Custom exception classes for clear error handling
- Context window management (maintains last 50 messages)
- Full type hints and comprehensive docstrings
- Structured logging system with `-v` flag for debug mode
- Interactive cmd2-based REPL with history and tab completion
- Centralized configuration via Config class

## Requirements

- Python 3.7+
- API key for your chosen LLM provider (OpenAI, Anthropic, Google, AWS, etc.)
  - For OpenAI: Set `OPENAI_API_KEY` environment variable
  - For Anthropic: Set `ANTHROPIC_API_KEY` environment variable
  - For Google: Set `GOOGLE_API_KEY` environment variable
  - See [aisuite documentation](https://github.com/andrewyng/aisuite) for other providers
- Network diagnostic tools installed: `ping`, `curl`, `dig`, `traceroute`, `whois`, `netstat` (or `ss`), `nc`
- **Optional (for mtr)**: `mtr` tool and sudo/root privileges

## Installation

1. Navigate to this directory:
   ```bash
   cd experiments/ai-agents/r2d2-agent
   ```

2. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set your API key for your chosen provider:
   ```bash
   # For OpenAI (default)
   export OPENAI_API_KEY='your-api-key-here'

   # Or for Anthropic
   export ANTHROPIC_API_KEY='your-api-key-here'

   # Or for Google
   export GOOGLE_API_KEY='your-api-key-here'

   # See aisuite docs for other providers
   ```

5. (Optional) Configure the model in `main.py`:
   ```python
   # In Config class, change MODEL to your preferred provider:model
   MODEL = "openai:gpt-4o"           # OpenAI GPT-4o (default)
   # MODEL = "anthropic:claude-3-5-sonnet-20241022"  # Anthropic Claude 3.5 Sonnet
   # MODEL = "google:gemini-1.5-pro"  # Google Gemini 1.5 Pro
   ```

## Usage

Run the agent:
```bash
python main.py           # Normal mode (WARNING level logging - quiet)
python main.py -v        # Verbose mode (INFO level logging - shows tool invocations)
python main.py -vv       # Very verbose mode (DEBUG level logging - detailed debug info)
python main.py --verbose # Same as -v

# Run with sudo to enable mtr tool (use -E to preserve environment variables)
sudo -E python main.py   # Enables privileged tools like mtr
# Alternative: explicitly pass the API key
sudo OPENAI_API_KEY="$OPENAI_API_KEY" python main.py
```

**Logging Levels:**
- **Default** (no flags): WARNING - Only errors and warnings
- **-v**: INFO - Shows tool invocations and important events
- **-vv**: DEBUG - Detailed debug information including successful completions

Example interaction:
```
R2D2> Can you check if example.com is reachable?
⠸ R2D2 is thinking...
R2D2>; *beep boop* Let me ping example.com for you! ... [executes ping] ...
       Yes, example.com is reachable with an average response time of 23ms!

R2D2> What's the DNS information for google.com?
⠴ R2D2 is thinking...
R2D2>; *excited droid noises* Running a DNS lookup... [executes dig] ...
       Here's what I found: google.com has multiple A records pointing to...
```

**Progress Indicator**: While R2D2 is processing your request (calling AI and executing tools), you'll see an animated spinner: `⠸ R2D2 is thinking...`

## Available Tools

| Tool | Description | Timeout | Requirements |
|------|-------------|---------|--------------|
| `ping` | Test network connectivity to a host | 30 seconds | - |
| `curl` | Fetch content from a URL | 60 seconds | - |
| `traceroute` | Trace network path to a host | 90 seconds | - |
| `dig` | Perform DNS lookup with trace | 45 seconds | - |
| `whois` | Look up domain registration information | 30 seconds | - |
| `netstat` | Show network connections and listening ports | 10 seconds | - |
| `nc` | Test if a TCP port is open on a host | 10 seconds | - |
| `mtr` | My Traceroute - combines ping and traceroute with statistics | 60 seconds | **Requires sudo** |

## Configuration

All settings are centralized in the `Config` class (main.py):

```python
class Config:
    # Context management
    MAX_CONTEXT_MESSAGES = 500  # Maximum conversation history

    # Tool timeouts (in seconds)
    PING_TIMEOUT = 30
    CURL_TIMEOUT = 60
    TRACEROUTE_TIMEOUT = 90
    DIG_TIMEOUT = 45
    WHOIS_TIMEOUT = 30
    NETSTAT_TIMEOUT = 10
    NC_TIMEOUT = 10
    MTR_TIMEOUT = 60  # Privileged tool (requires sudo)

    # Threading
    MAX_CONCURRENT_TOOLS = 8

    # Logging
    LOG_LEVEL = "WARNING"  # Default level (use -v or -vv to increase)
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # AI Provider settings
    # Format: "provider:model"
    # Examples:
    #   - "openai:gpt-4o"
    #   - "anthropic:claude-3-5-sonnet-20241022"
    #   - "google:gemini-1.5-pro"
    MODEL = "openai:gpt-4o"
    SYSTEM_PROMPT = "you're R2D2. Your job is to help..."
```

### Switching Between AI Providers

R2D2 uses [aisuite](https://github.com/andrewyng/aisuite) which provides a unified interface to multiple AI providers. To switch providers:

1. Install the provider-specific package (if needed):
   ```bash
   pip install 'aisuite[anthropic]'  # For Anthropic
   pip install 'aisuite[google]'     # For Google
   pip install 'aisuite[all]'        # For all providers
   ```

2. Set the appropriate API key environment variable

3. Update the `MODEL` setting in `Config` class to use the format `"provider:model"`


## Tool Execution Flow

1. User sends request to R2D2
2. AI model determines which tool(s) to call
3. Input validation (prevents command injection)
4. Execute command with timeout
5. Check return code for errors
6. Return results to AI model
7. AI model formulates response to user

## Limitations

- Requires API key for chosen LLM provider (API calls incur costs)
- Network tools must be installed on the system
- `traceroute` may require root privileges (uses `-I` flag for ICMP)
- `mtr` requires sudo/root privileges to run
- Context limited to last 500 messages
- Not all AI providers may support function calling (tool use) - OpenAI, Anthropic, and Google models are recommended

## License

MIT License

## Credits

Inspired by the blog post: [Everyone, Write an Agent!](https://fly.io/blog/everyone-write-an-agent/)
