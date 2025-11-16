# R2D2 - AI Network Diagnostic Agent

An AI-powered assistant that executes network diagnostic tools like ping, curl, dig, and traceroute to help software engineers debug network issues.

Inspired by: https://fly.io/blog/everyone-write-an-agent/

## Features

- AI-powered conversational interface using OpenAI
- Executes network diagnostic commands: `ping`, `curl`, `dig`, `traceroute`
- Comprehensive input validation (RFC 1123 hostname validation, URL validation)
- Structured logging system
- Centralized configuration via Config class

## Requirements

- Python 3.7+
- OpenAI API key
- Network diagnostic tools installed: `ping`, `curl`, `dig`, `traceroute`

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

4. Set your OpenAI API key:
   ```bash
   export OPENAI_API_KEY='your-api-key-here'
   ```

## Usage

Run the agent:
```bash
python main.py        # Normal mode (INFO level logging)
python main.py -v     # Verbose mode (DEBUG level logging)
python main.py --verbose  # Same as -v
```

Example interaction:
```
R2D2> Can you check if example.com is reachable?
R2D2>; *beep boop* Let me ping example.com for you! ... [executes ping] ...
       Yes, example.com is reachable with an average response time of 23ms!

R2D2> What's the DNS information for google.com?
R2D2>; *excited droid noises* Running a DNS lookup... [executes dig] ...
       Here's what I found: google.com has multiple A records pointing to...
```

**Verbose Mode**: When running with `-v` flag, you'll see additional debug logs including:
- Successful command completions
- Detailed function call information
- Internal state changes

## Available Tools

| Tool | Description | Timeout |
|------|-------------|---------|
| `ping` | Test network connectivity to a host | 30 seconds |
| `curl` | Fetch content from a URL | 60 seconds |
| `traceroute` | Trace network path to a host | 90 seconds |
| `dig` | Perform DNS lookup with trace | 45 seconds |

## Configuration

All settings are centralized in the `Config` class (main.py:27-52):

```python
class Config:
    # Context management
    MAX_CONTEXT_MESSAGES = 50  # Maximum conversation history

    # Tool timeouts (in seconds)
    PING_TIMEOUT = 30
    CURL_TIMEOUT = 60
    TRACEROUTE_TIMEOUT = 90
    DIG_TIMEOUT = 45

    # Logging
    LOG_LEVEL = "INFO"
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # OpenAI settings
    MODEL = "gpt-5"
    SYSTEM_PROMPT = "you're R2D2. Your job is to help..."
```


## Tool Execution Flow

1. User sends request to R2D2
2. OpenAI determines which tool(s) to call
3. Input validation (prevents command injection)
4. Execute command with timeout
5. Check return code for errors
6. Return results to OpenAI
7. OpenAI formulates response to user

## Limitations

- Requires OpenAI API key (API calls incur costs)
- Network tools must be installed on the system
- `traceroute` may require root privileges (uses `-I` flag for ICMP)
- Context limited to last 50 messages

## License

MIT License

## Credits

Inspired by the blog post: [Everyone, Write an Agent!](https://fly.io/blog/everyone-write-an-agent/)
