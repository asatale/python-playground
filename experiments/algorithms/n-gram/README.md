# N-gram Generator

## Overview

This project implements an n-gram generator in Python. An **n-gram** is a contiguous sequence of n characters (or tokens) from a given text. N-grams are fundamental in natural language processing, text analysis, and machine learning applications.

## What are N-grams?

N-grams are sequences of consecutive characters extracted from text using a sliding window approach:

- **Unigram (n=1)**: Single characters: "a", "b", "c"
- **Bigram (n=2)**: Two-character sequences: "ab", "bc", "cd"
- **Trigram (n=3)**: Three-character sequences: "abc", "bcd", "cde"
- **N-gram (n=n)**: N-character sequences

### Example

For the word **"castle"** with window size 3 (trigrams):
- Position 0-2: "cas"
- Position 1-3: "ast"
- Position 2-4: "stl"
- Position 3-5: "tle"

Result: `["cas", "ast", "stl", "tle"]`

## Features

- Generate n-grams of any window size
- Handle edge cases (empty strings, window larger than text)
- Input validation with clear error messages
- Comprehensive test suite included

## Usage

### Basic Usage

```python
from ngram import ngram

# Generate trigrams (3-character sequences)
result = ngram("castle", 3)
print(result)  # ['cas', 'ast', 'stl', 'tle']

# Generate bigrams (2-character sequences)
result = ngram("test", 2)
print(result)  # ['te', 'es', 'st']

# Generate 4-grams
result = ngram("alphabet", 4)
print(result)  # ['alph', 'lpha', 'phab', 'habe', 'abet']
```

### Running the Demo

```bash
python ngram.py
```

### Running Tests

The project includes a comprehensive test suite using Python's unittest framework:

```bash
# Run all tests
python test_ngram.py

# Run with verbose output
python test_ngram.py -v

# Run using unittest discovery
python -m unittest test_ngram
```

## API Reference

### `ngram(text: str, window: int = 3) -> list[str]`

Generate n-grams from the input text.

**Parameters:**
- `text` (str): The input string to generate n-grams from
- `window` (int, optional): Size of the n-gram window. Default is 3.

**Returns:**
- `list[str]`: List of n-gram strings of length 'window'. Returns empty list if window size is larger than the text length.

**Raises:**
- `ValueError`: If window size is less than 1
- `TypeError`: If text is not a string

## Applications

N-grams are commonly used in:

1. **Text Analysis**: Frequency analysis, pattern recognition
2. **Natural Language Processing**: Language modeling, text prediction
3. **Spell Checking**: Detecting and correcting misspellings
4. **Text Similarity**: Comparing documents for plagiarism detection
5. **Machine Learning**: Feature extraction for text classification
6. **Cryptography**: Pattern analysis and frequency attacks

## Requirements

This project uses only Python's standard library. No external dependencies are required.

- Python 3.9+ (uses modern type hints with `list[str]`)

## License

This is an educational project for algorithm exploration.
