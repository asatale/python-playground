# Python Playground

A collection of Python experiments, algorithms, and explorations. Each experiment is self-contained with its own dependencies and documentation.

## Structure

```
python-playground/
├── experiments/
│   ├── algorithms/          # Algorithm implementations
│   ├── ai-agents/           # AI-powered agents and tools
│   ├── data-structures/     # Data structure implementations
│   ├── web-scraping/        # Web scraping experiments
│   ├── machine-learning/    # ML/AI experiments
│   └── misc/                # Miscellaneous experiments
```

## Experiments

### Algorithms

- **[infix-to-postfix](experiments/algorithms/infix-to-postfix/)** - Converts infix mathematical expressions to postfix notation using the Shunting Yard algorithm. Includes comprehensive test suite and handles operator precedence, associativity, and unary operators.
- **[n-gram](experiments/algorithms/n-gram/)** - Generates n-grams (contiguous sequences of n characters) from text using a sliding window approach. Useful for text analysis, NLP, and pattern recognition applications.

### AI Agents

- **[r2d2-agent](experiments/ai-agents/r2d2-agent/)** - AI-powered network diagnostic agent using OpenAI. Executes ping, curl, dig, and traceroute commands with comprehensive input validation, error handling, and security features. Inspired by [fly.io blog post](https://fly.io/blog/everyone-write-an-agent/).

## Getting Started

Each experiment has its own directory with:
- `README.md` - Description and usage instructions
- `requirements.txt` - Python dependencies
- Source code and tests

### Running an Experiment

1. Navigate to the experiment directory:
   ```bash
   cd experiments/algorithms/infix-to-postfix
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

4. Run the code or tests as documented in the experiment's README.

## Contributing

This is a personal playground for Python experiments. Feel free to explore the code!

## License

MIT License - see LICENSE file for details.
