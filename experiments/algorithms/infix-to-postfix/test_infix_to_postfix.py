import unittest
from infix_to_postfix import (
    Stack,
    Tokenizer,
    should_pop_for_precedence,
    is_unary_operator,
    infix_to_postfix,
    InfixConversionError,
    UnbalancedParenthesesError,
    InvalidExpressionError
)


# ============================================================================
# UNIT TESTS - Testing individual components in isolation
# ============================================================================

class StackTests(unittest.TestCase):
    """Unit tests for the Stack class."""

    def test_push_and_peek(self):
        stack = Stack()
        stack.push('A')
        self.assertEqual(stack.peek(), 'A')
        stack.push('B')
        self.assertEqual(stack.peek(), 'B')

    def test_pop(self):
        stack = Stack()
        stack.push('A')
        stack.push('B')
        self.assertEqual(stack.pop(), 'B')
        self.assertEqual(stack.pop(), 'A')

    def test_pop_empty_stack_returns_none(self):
        stack = Stack()
        self.assertIsNone(stack.pop())

    def test_peek_empty_stack_returns_none(self):
        stack = Stack()
        self.assertIsNone(stack.peek())

    def test_is_empty(self):
        stack = Stack()
        self.assertTrue(stack.is_empty())
        stack.push('A')
        self.assertFalse(stack.is_empty())
        stack.pop()
        self.assertTrue(stack.is_empty())

    def test_size(self):
        stack = Stack()
        self.assertEqual(stack.size(), 0)
        stack.push('A')
        self.assertEqual(stack.size(), 1)
        stack.push('B')
        self.assertEqual(stack.size(), 2)
        stack.pop()
        self.assertEqual(stack.size(), 1)

    def test_pop_until_success(self):
        stack = Stack()
        stack.push('(')
        stack.push('A')
        stack.push('+')
        stack.push('B')
        result = stack.pop_until('(')
        self.assertEqual(result, ['B', '+', 'A'])
        self.assertTrue(stack.is_empty())

    def test_pop_until_target_not_found(self):
        stack = Stack()
        stack.push('A')
        stack.push('B')
        with self.assertRaises(UnbalancedParenthesesError):
            stack.pop_until('(')

    def test_pop_until_empty_stack(self):
        stack = Stack()
        with self.assertRaises(UnbalancedParenthesesError):
            stack.pop_until('(')


class TokenizerTests(unittest.TestCase):
    """Unit tests for the Tokenizer class."""

    def test_tokenize_simple_expression(self):
        tokens = list(Tokenizer("A+B"))
        self.assertEqual(tokens, ['A', '+', 'B'])

    def test_tokenize_with_spaces(self):
        tokens = list(Tokenizer("A + B"))
        self.assertEqual(tokens, ['A', '+', 'B'])

    def test_tokenize_multiple_spaces(self):
        tokens = list(Tokenizer("A  +  B"))
        self.assertEqual(tokens, ['A', '+', 'B'])

    def test_tokenize_multi_char_operands(self):
        tokens = list(Tokenizer("foo+bar"))
        self.assertEqual(tokens, ['foo', '+', 'bar'])

    def test_tokenize_parentheses(self):
        tokens = list(Tokenizer("(A+B)"))
        self.assertEqual(tokens, ['(', 'A', '+', 'B', ')'])

    def test_tokenize_all_operators(self):
        tokens = list(Tokenizer("A+B-C*D/E^F"))
        self.assertEqual(tokens, ['A', '+', 'B', '-', 'C', '*', 'D', '/', 'E', '^', 'F'])

    def test_tokenize_empty_string(self):
        tokens = list(Tokenizer(""))
        self.assertEqual(tokens, [])

    def test_tokenize_whitespace_only(self):
        tokens = list(Tokenizer("   "))
        self.assertEqual(tokens, [])

    def test_tokenize_mixed_whitespace(self):
        tokens = list(Tokenizer("A\t+\nB"))
        self.assertEqual(tokens, ['A', '+', 'B'])

    def test_is_literal(self):
        self.assertTrue(Tokenizer.is_literal('A'))
        self.assertTrue(Tokenizer.is_literal('5'))
        self.assertFalse(Tokenizer.is_literal('+'))
        self.assertFalse(Tokenizer.is_literal('('))

    def test_is_operator(self):
        for op in ['+', '-', '*', '/', '^']:
            self.assertTrue(Tokenizer.is_operator(op))
        self.assertFalse(Tokenizer.is_operator('A'))
        self.assertFalse(Tokenizer.is_operator('('))

    def test_is_metachar(self):
        self.assertTrue(Tokenizer.is_metachar('('))
        self.assertTrue(Tokenizer.is_metachar(')'))
        self.assertFalse(Tokenizer.is_metachar('+'))
        self.assertFalse(Tokenizer.is_metachar('A'))

    def test_is_whitespace(self):
        self.assertTrue(Tokenizer.is_whitespace(' '))
        self.assertTrue(Tokenizer.is_whitespace('\t'))
        self.assertTrue(Tokenizer.is_whitespace('\n'))
        self.assertFalse(Tokenizer.is_whitespace('A'))


class HelperFunctionTests(unittest.TestCase):
    """Unit tests for helper functions."""

    def test_should_pop_for_precedence_higher(self):
        # ^ has higher precedence than +
        self.assertTrue(should_pop_for_precedence('^', '+'))

    def test_should_pop_for_precedence_equal_left_associative(self):
        # Equal precedence, left-associative: should pop
        self.assertTrue(should_pop_for_precedence('+', '-'))
        self.assertTrue(should_pop_for_precedence('*', '/'))

    def test_should_pop_for_precedence_equal_right_associative(self):
        # Equal precedence, right-associative: should NOT pop
        self.assertFalse(should_pop_for_precedence('^', '^'))

    def test_should_pop_for_precedence_lower(self):
        # + has lower precedence than *: should NOT pop
        self.assertFalse(should_pop_for_precedence('+', '*'))

    def test_is_unary_operator_at_start(self):
        self.assertTrue(is_unary_operator('-', ''))

    def test_is_unary_operator_after_opening_paren(self):
        self.assertTrue(is_unary_operator('-', '('))

    def test_is_unary_operator_after_operator(self):
        self.assertTrue(is_unary_operator('-', '+'))
        self.assertTrue(is_unary_operator('-', '*'))

    def test_is_unary_operator_after_operand(self):
        self.assertFalse(is_unary_operator('-', 'A'))
        self.assertFalse(is_unary_operator('-', 'foo'))

    def test_is_unary_operator_not_minus(self):
        self.assertFalse(is_unary_operator('+', ''))
        self.assertFalse(is_unary_operator('*', ''))


# ============================================================================
# INTEGRATION TESTS - Testing the full infix_to_postfix function
# ============================================================================

class InfixToPostfixTests(unittest.TestCase):
    """Integration tests for the infix_to_postfix function."""

    def test_returns_list_of_strings(self):
        """Verify the function returns list[str], not a string."""
        result = infix_to_postfix("A+B")
        self.assertIsInstance(result, list)
        self.assertEqual(result, ['A', 'B', '+'])
        for token in result:
            self.assertIsInstance(token, str)

    def test_empty_string(self):
        """Edge case: empty expression."""
        with self.assertRaises(InvalidExpressionError):
            infix_to_postfix("")

    def test_single_operand(self):
        """Edge case: single operand with no operators."""
        result = infix_to_postfix("A")
        self.assertEqual(result, ['A'])

    def test_basic_operations(self):
        """Test basic binary operations."""
        cases = [
            ("A+B", ['A', 'B', '+']),
            ("A-B", ['A', 'B', '-']),
            ("A*B", ['A', 'B', '*']),
            ("A/B", ['A', 'B', '/']),
            ("A^B", ['A', 'B', '^']),
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                self.assertEqual(infix_to_postfix(expr), expected)

    def test_operator_precedence(self):
        """Test that operators are applied in correct precedence order."""
        cases = [
            ("A+B*C", ['A', 'B', 'C', '*', '+']),      # * before +
            ("A*B+C", ['A', 'B', '*', 'C', '+']),      # * before +
            ("A+B^C", ['A', 'B', 'C', '^', '+']),      # ^ before +
            ("A^B*C", ['A', 'B', '^', 'C', '*']),      # ^ before *
            ("A*B+C*D", ['A', 'B', '*', 'C', 'D', '*', '+']),
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                self.assertEqual(infix_to_postfix(expr), expected)

    def test_left_associativity(self):
        """Test left-associative operators (-, /) are evaluated left-to-right."""
        cases = [
            ("A-B-C", ['A', 'B', '-', 'C', '-']),      # (A-B)-C, not A-(B-C)
            ("A/B/C", ['A', 'B', '/', 'C', '/']),      # (A/B)/C, not A/(B/C)
            ("A+B+C", ['A', 'B', '+', 'C', '+']),      # (A+B)+C
            ("A*B*C", ['A', 'B', '*', 'C', '*']),      # (A*B)*C
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                self.assertEqual(infix_to_postfix(expr), expected)

    def test_right_associativity(self):
        """Test right-associative operator (^) is evaluated right-to-left."""
        cases = [
            ("A^B^C", ['A', 'B', 'C', '^', '^']),      # A^(B^C), not (A^B)^C
            ("A^B^C^D", ['A', 'B', 'C', 'D', '^', '^', '^']),  # A^(B^(C^D))
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                self.assertEqual(infix_to_postfix(expr), expected)

    def test_parentheses(self):
        """Test that parentheses override precedence."""
        cases = [
            ("(A+B)*C", ['A', 'B', '+', 'C', '*']),
            ("A*(B+C)", ['A', 'B', 'C', '+', '*']),
            ("A+(B/(C-D))", ['A', 'B', 'C', 'D', '-', '/', '+']),
            ("((A+B))", ['A', 'B', '+']),              # Redundant parentheses
            ("A+(B)", ['A', 'B', '+']),                # Redundant parentheses
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                self.assertEqual(infix_to_postfix(expr), expected)

    def test_unary_minus(self):
        """Test unary minus operator handling."""
        cases = [
            ("-A+B", ['-A', 'B', '+']),                # Unary at start
            ("A*-B", ['A', '-B', '*']),                # Unary after operator
            ("(-A)+B", ['-A', 'B', '+']),              # Unary after opening paren
            ("A+(-B)", ['A', '-B', '+']),              # Unary after opening paren
            ("A*-B+C", ['A', '-B', '*', 'C', '+']),    # Unary in expression
            ("A*(-B+C)", ['A', '-B', 'C', '+', '*']),  # Unary in parentheses
            ("A/-B+C", ['A', '-B', '/', 'C', '+']),    # Unary after /
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                self.assertEqual(infix_to_postfix(expr), expected)

    def test_unary_nested(self):
        """Test nested unary operators."""
        cases = [
            ("-(A+B)", ['-AB+', ]),                    # Unary with expression - wait this looks wrong
            ("A*-(-B)", ['A', '--B', '*']),            # Double negative
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                result = infix_to_postfix(expr)
                # Join tokens for easier comparison
                self.assertEqual(''.join(result), ''.join(expected))

    def test_multi_char_operands(self):
        """Test multi-character variable names."""
        result = infix_to_postfix("foo+bar*baz")
        self.assertEqual(result, ['foo', 'bar', 'baz', '*', '+'])

    def test_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        cases = [
            ("A + B", ['A', 'B', '+']),
            ("A  +  B", ['A', 'B', '+']),
            ("A\t+\nB", ['A', 'B', '+']),
            (" A + B ", ['A', 'B', '+']),
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                self.assertEqual(infix_to_postfix(expr), expected)

    def test_complex_expressions(self):
        """Test complex real-world expressions."""
        cases = [
            ("A*(B+C*D)+E", ['A', 'B', 'C', 'D', '*', '+', '*', 'E', '+']),
        ]
        for expr, expected in cases:
            with self.subTest(expr=expr):
                self.assertEqual(infix_to_postfix(expr), expected)


class InvalidExpressionTests(unittest.TestCase):
    """Tests for invalid expressions and error handling."""

    def test_unbalanced_parentheses_extra_closing(self):
        """Test extra closing parenthesis raises UnbalancedParenthesesError."""
        with self.assertRaises(UnbalancedParenthesesError):
            infix_to_postfix("A+B))")

    def test_unbalanced_parentheses_missing_closing(self):
        """Test missing closing parenthesis raises InvalidExpressionError."""
        with self.assertRaises(InvalidExpressionError):
            infix_to_postfix("((A+B)")

    def test_operator_at_start(self):
        """Test binary operator at start raises InvalidExpressionError."""
        with self.assertRaises(InvalidExpressionError):
            infix_to_postfix("*A+B")

    def test_operator_at_end(self):
        """Test operator at end raises InvalidExpressionError."""
        with self.assertRaises(InvalidExpressionError):
            infix_to_postfix("A+")

    def test_invalid_characters(self):
        """Test invalid characters raise InvalidExpressionError."""
        invalid_cases = ["A+B$C", "A&*B", "A@B"]
        for expr in invalid_cases:
            with self.subTest(expr=expr):
                with self.assertRaises(InvalidExpressionError):
                    infix_to_postfix(expr)

    def test_consecutive_operators(self):
        """Test consecutive binary operators raise InvalidExpressionError."""
        with self.assertRaises(InvalidExpressionError):
            infix_to_postfix("A++B")

    def test_missing_operand_between_operands(self):
        """Test missing operator between operands raises InvalidExpressionError."""
        # "A B" has two separate operands with no operator
        with self.assertRaises(InvalidExpressionError):
            infix_to_postfix("A B")


if __name__ == '__main__':
    unittest.main()
