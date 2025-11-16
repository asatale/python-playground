from typing import Optional

# Custom exceptions for infix to postfix conversion
class InfixConversionError(Exception):
    """Base exception for infix to postfix conversion errors."""
    pass


class UnbalancedParenthesesError(InfixConversionError):
    """Raised when parentheses are not properly balanced in the expression."""
    pass


class InvalidExpressionError(InfixConversionError):
    """Raised when the expression is malformed or contains invalid elements."""
    pass


class Stack:
    """
    A simple stack data structure supporting push, pop, peek, and utility operations.

    Used for managing operators and parentheses during infix to postfix conversion.
    """

    def __init__(self) -> None:
        """Initialize an empty stack."""
        self._items: list[str] = []

    def push(self, item: str) -> None:
        """
        Push an item onto the stack.

        Args:
            item: The item to push onto the stack
        """
        self._items.append(item)

    def peek(self) -> Optional[str]:
        """
        Return the top item without removing it.

        Returns:
            The top item on the stack, or None if the stack is empty
        """
        return self._items[-1] if self._items else None

    def is_empty(self) -> bool:
        """
        Check if the stack is empty.

        Returns:
            bool: True if the stack is empty, False otherwise
        """
        return len(self._items) == 0

    def size(self) -> int:
        """
        Get the number of items in the stack.

        Returns:
            int: The number of items in the stack
        """
        return len(self._items)

    def pop(self) -> Optional[str]:
        """
        Remove and return the top item from the stack.

        Returns:
            The top item from the stack, or None if the stack is empty
        """
        if not self.is_empty():
            return self._items.pop()
        else:
            return None

    def pop_until(self, target: str) -> list[str]:
        """
        Pop items from the stack until the target item is found.

        The target item is also removed from the stack but not included in the result.

        Args:
            target: The item to search for (typically an opening parenthesis)

        Returns:
            list: A list of all items popped before finding the target

        Raises:
            UnbalancedParenthesesError: If the target item is not found in the stack
        """
        popped_items = []
        while not self.is_empty() and self.peek() != target:
            popped_items.append(self.pop())
        if self.peek() != target:
            raise UnbalancedParenthesesError(f"Matching {target} not found")
        self.pop()
        return popped_items


# Constants for operators and metacharacters
OPERATORS = {'+', '-', '*', '/', '^'}
OPENING_PAREN = '('
CLOSING_PAREN = ')'
METACHARACTERS = {OPENING_PAREN, CLOSING_PAREN}
WHITESPACE = {' ', '\n', '\t'}

# Operator precedence levels (higher number = higher precedence)
OPERATOR_PRECEDENCE = {
    '+': 1,
    '-': 1,
    '*': 2,
    '/': 2,
    '^': 3
}

# Right-associative operators
RIGHT_ASSOCIATIVE = {'^'}


def should_pop_for_precedence(stack_op: str, current_op: str) -> bool:
    """
    Returns True if stack_op should be popped when current_op is encountered.

    For left-associative operators: pop if stack_op has higher or equal precedence
    For right-associative operators: pop only if stack_op has strictly higher precedence

    Args:
        stack_op: Operator currently on top of the stack
        current_op: Operator being processed from input

    Returns:
        bool: True if stack_op should be popped, False otherwise
    """
    stack_prec = OPERATOR_PRECEDENCE[stack_op]
    current_prec = OPERATOR_PRECEDENCE[current_op]

    if current_op in RIGHT_ASSOCIATIVE:
        # For right-associative: only pop if strictly higher precedence
        return stack_prec > current_prec
    else:
        # For left-associative: pop if higher or equal precedence
        return stack_prec >= current_prec


def is_unary_operator(current: str, last: str) -> bool:
    """
    Determine if an operator is being used as a unary operator.

    A minus sign is considered unary if it appears:
    - At the start of the expression (last == "")
    - After an opening parenthesis
    - After another operator

    Args:
        current: The current operator being examined
        last: The previous token in the expression

    Returns:
        bool: True if the operator is unary, False otherwise

    Example:
        is_unary_operator("-", "") -> True (start of expression)
        is_unary_operator("-", "(") -> True (after opening paren)
        is_unary_operator("-", "*") -> True (after operator)
        is_unary_operator("-", "A") -> False (after operand)
    """
    return current == "-" and last in ({"", OPENING_PAREN} | OPERATORS)


def handle_operator(current: str, last: str, result: list[str], stack: Stack) -> None:
    """
    Process a binary operator according to precedence rules.

    Pops operators from the stack to the result based on precedence and associativity,
    then pushes the current operator onto the stack.

    Args:
        current: The current operator being processed
        last: The previous token (unused, kept for consistency)
        result: The output list where operators are appended
        stack: The operator stack

    Note:
        This function modifies both result and stack in place.
    """
    while not stack.is_empty():
        stack_top = stack.peek()
        # Don't pop past opening parenthesis
        if stack_top == OPENING_PAREN:
            break
        if should_pop_for_precedence(stack_top, current):
            result.append(stack.pop())
        else:
            break
    stack.push(current)


class Tokenizer:
    """
    Iterator that tokenizes an infix expression string.

    Breaks the expression into tokens: operators, parentheses, and operands.
    Whitespace is automatically skipped between and within tokens.

    Example:
        >>> list(Tokenizer("A + B * C"))
        ['A', '+', 'B', '*', 'C']
        >>> list(Tokenizer("foo + bar"))
        ['foo', '+', 'bar']
    """

    def __init__(self, expr: str) -> None:
        """
        Initialize the tokenizer with an expression string.

        Args:
            expr: The infix expression string to tokenize
        """
        self.expr: str = expr
        self.idx: int = 0

    @staticmethod
    def is_literal(char: str) -> bool:
        """
        Check if a character is a literal (alphanumeric).

        Args:
            char: The character to check

        Returns:
            bool: True if the character is alphanumeric, False otherwise
        """
        return char.isalnum()

    @staticmethod
    def is_operator(char: str) -> bool:
        """
        Check if a character is an operator.

        Args:
            char: The character to check

        Returns:
            bool: True if the character is an operator (+, -, *, /, ^), False otherwise
        """
        return char in OPERATORS

    @staticmethod
    def is_metachar(char: str) -> bool:
        """
        Check if a character is a metacharacter (parenthesis).

        Args:
            char: The character to check

        Returns:
            bool: True if the character is a parenthesis, False otherwise
        """
        return char in METACHARACTERS

    @staticmethod
    def is_whitespace(char: str) -> bool:
        """
        Check if a character is whitespace.

        Args:
            char: The character to check

        Returns:
            bool: True if the character is whitespace, False otherwise
        """
        return char in WHITESPACE

    def __iter__(self) -> 'Tokenizer':
        """Return the iterator object (self)."""
        return self

    def __next__(self) -> str:
        """
        Get the next token from the expression.

        Returns:
            str: The next token (operator, parenthesis, or operand)

        Raises:
            StopIteration: When there are no more tokens
        """
        # Skip whitespaces
        while self.idx < len(self.expr) and self.is_whitespace(self.expr[self.idx]):
            self.idx += 1

        token = ""
        if self.idx < len(self.expr):
            char = self.expr[self.idx]
            if self.is_operator(char) or self.is_metachar(char):
                self.idx += 1
                token = char
            else:
                # Build multi-character token, skipping whitespace
                while self.idx < len(self.expr) \
                      and not (self.is_operator(self.expr[self.idx]) \
                               or self.is_metachar(self.expr[self.idx]) \
                               or self.is_whitespace(self.expr[self.idx])):
                    token += self.expr[self.idx]
                    self.idx += 1
        if token:
            return token
        else:
            raise StopIteration


def validate_postfix_expression(expr: list[str]) -> bool:
    """
    Validate that a postfix expression is well-formed.

    Checks that:
    - No metacharacters (parentheses) are present
    - Each operator has sufficient operands (at least 2)
    - All tokens contain only valid characters
    - The final result is a single operand

    Args:
        expr: List of tokens in postfix notation

    Returns:
        bool: True if the expression is valid, False otherwise

    Example:
        >>> validate_postfix_expression(['A', 'B', '+'])
        True
        >>> validate_postfix_expression(['A', '+'])  # Not enough operands
        False
        >>> validate_postfix_expression(['A', 'B', '+', '('])  # Contains parenthesis
        False
    """
    stack = Stack()
    for token in expr:
        if Tokenizer.is_metachar(token):
            return False
        if Tokenizer.is_operator(token):
            if stack.size() < 2:
                return False
            a, b = stack.pop(), stack.pop()
            stack.push(f"{b}{token}{a}")
        else:
            # multi-char literal or negative literal
            for char in token:
                if Tokenizer.is_literal(char) or char == '-':
                    continue
                else:
                    return False
            stack.push(token)

    if stack.size() == 1 and not Tokenizer.is_operator(stack.peek()):
        return True

    return False


def infix_to_postfix(expr: str) -> list[str]:
    """
    Convert an infix expression to postfix (Reverse Polish Notation).

    Uses the Shunting Yard algorithm to convert infix expressions to postfix notation,
    handling operator precedence, associativity, parentheses, and unary minus operators.

    Operator Precedence (highest to lowest):
        ^ (exponentiation) - right-associative
        *, / (multiplication, division) - left-associative
        +, - (addition, subtraction) - left-associative

    Args:
        expr: The infix expression string (e.g., "A + B * C")

    Returns:
        list[str]: List of tokens in postfix notation (e.g., ['A', 'B', 'C', '*', '+'])

    Raises:
        UnbalancedParenthesesError: If parentheses are not properly matched
        InvalidExpressionError: If the expression is malformed (invalid characters,
                                insufficient operands, etc.)

    Example:
        >>> infix_to_postfix("A+B")
        ['A', 'B', '+']
        >>> infix_to_postfix("(A+B)*C")
        ['A', 'B', '+', 'C', '*']
        >>> infix_to_postfix("-A+B")
        ['-A', 'B', '+']
        >>> infix_to_postfix("A^B^C")  # Right-associative
        ['A', 'B', 'C', '^', '^']
    """
    stack = Stack()
    unary = Stack()
    result = []
    last = ""

    for current in Tokenizer(expr):
        if current == OPENING_PAREN:
            stack.push(current)
        elif current == CLOSING_PAREN:
            result += stack.pop_until(OPENING_PAREN)
        elif Tokenizer.is_operator(current):
            if is_unary_operator(current, last):
                unary.push(current)
            else:
                handle_operator(current, last, result, stack)
        else:
            while not unary.is_empty():
                current = unary.pop()+current
            result.append(current)
        last = current

    while not stack.is_empty():
        result.append(stack.pop())

    if validate_postfix_expression(result):
        return result

    raise InvalidExpressionError(f"Invalid infix expression: {expr}, postfix: {result}")
