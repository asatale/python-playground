# Infix to Postfix Converter

A Python implementation of the Shunting Yard algorithm for converting infix mathematical expressions to postfix (Reverse Polish Notation).

## Features

- ✅ Converts infix expressions to postfix notation
- ✅ Supports all basic operators: `+`, `-`, `*`, `/`, `^`
- ✅ Handles operator precedence correctly
- ✅ Supports left and right associativity
- ✅ Handles unary minus operator
- ✅ Multi-character variable names
- ✅ Comprehensive error handling with custom exceptions
- ✅ Full type hints
- ✅ 51 comprehensive unit and integration tests

## Operator Precedence

| Operator | Precedence | Associativity |
|----------|------------|---------------|
| `^`      | 3 (highest)| Right         |
| `*`, `/` | 2          | Left          |
| `+`, `-` | 1 (lowest) | Left          |

## Installation

No external dependencies required - uses only Python standard library.

```bash
# Optional: Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Optional: Install development dependencies
pip install -r requirements.txt
```

## Usage

```python
from infix_to_postfix import infix_to_postfix

# Basic usage
result = infix_to_postfix("A+B*C")
print(result)  # ['A', 'B', 'C', '*', '+']

# With parentheses
result = infix_to_postfix("(A+B)*C")
print(result)  # ['A', 'B', '+', 'C', '*']

# Right-associative operator
result = infix_to_postfix("A^B^C")
print(result)  # ['A', 'B', 'C', '^', '^']  # A^(B^C)

# Unary minus
result = infix_to_postfix("-A+B")
print(result)  # ['-A', 'B', '+']

# Multi-character variables
result = infix_to_postfix("foo + bar * baz")
print(result)  # ['foo', 'bar', 'baz', '*', '+']
```

## Error Handling

The library uses custom exception types for clear error reporting:

```python
from infix_to_postfix import (
    infix_to_postfix,
    UnbalancedParenthesesError,
    InvalidExpressionError
)

try:
    result = infix_to_postfix("A+B))")
except UnbalancedParenthesesError as e:
    print(f"Parentheses error: {e}")

try:
    result = infix_to_postfix("A++B")
except InvalidExpressionError as e:
    print(f"Invalid expression: {e}")
```

## Running Tests

```bash
# Run all tests with verbose output
python test_infix_to_postfix.py -v

# Run specific test class
python -m unittest test_infix_to_postfix.StackTests

# Run with coverage (if pytest-cov installed)
pytest --cov=infix_to_postfix --cov-report=html
```

## Test Coverage

The project includes 51 comprehensive tests:
- **8 tests** for Stack class (unit tests)
- **13 tests** for Tokenizer class (unit tests)
- **9 tests** for helper functions (unit tests)
- **15 tests** for infix_to_postfix integration
- **6 tests** for error handling

All tests pass ✅

## Architecture

### Components

1. **Stack** - Generic stack implementation for operator management
2. **Tokenizer** - Breaks expression into tokens (operators, operands, parentheses)
3. **Precedence Handler** - Data-driven precedence and associativity logic
4. **Validator** - Ensures the generated postfix expression is valid

### Algorithm

Uses the Shunting Yard algorithm:
1. Read tokens from left to right
2. Operands go directly to output
3. Operators are pushed to stack based on precedence rules
4. Parentheses control evaluation order
5. Validate the final postfix expression

## Code Quality

- ✅ Full type hints using Python typing module
- ✅ Comprehensive docstrings (Google style)
- ✅ PEP 8 compliant (snake_case naming)
- ✅ Custom exception classes
- ✅ Constants for magic values
- ✅ Data-driven design (precedence table)

## Examples

### Left Associativity
```python
infix_to_postfix("A-B-C")
# ['A', 'B', '-', 'C', '-']  # (A-B)-C, not A-(B-C)
```

### Right Associativity
```python
infix_to_postfix("A^B^C")
# ['A', 'B', 'C', '^', '^']  # A^(B^C), not (A^B)^C
```

### Complex Expression
```python
infix_to_postfix("A*(B+C*D)+E")
# ['A', 'B', 'C', 'D', '*', '+', '*', 'E', '+']
```

## License

MIT License
