

def ngram(text: str, window: int = 3) -> list[str]:
    """
    Generate n-grams from the input text.

    An n-gram is a contiguous sequence of n characters from a given text.
    For example, the 3-grams (trigrams) of "castle" are: "cas", "ast", "stl", "tle".

    Args:
        text: The input string to generate n-grams from
        window: Size of the n-gram window (default: 3)

    Returns:
        List of n-gram strings of length 'window'. Returns empty list if
        window size is larger than the text length.

    Raises:
        ValueError: If window size is less than 1
        TypeError: If text is not a string

    Examples:
        >>> ngram("castle", 3)
        ['cas', 'ast', 'stl', 'tle']
        >>> ngram("test", 2)
        ['te', 'es', 'st']
        >>> ngram("ok", 5)
        []
    """
    if not isinstance(text, str):
        raise TypeError("Text must be a string")

    if window < 1:
        raise ValueError("Window size must be at least 1")

    return [text[i:i + window] for i in range(len(text) - window + 1)]


def main():
    """Demo function showing basic usage of ngram."""
    print("3-grams of 'castle':", ngram("castle", 3))
    print("3-grams of 'test':", ngram("test", 3))
    print("3-grams of 'ok' (window too large):", ngram("ok", 3))
    print("4-grams of 'alphabet':", ngram("alphabet", 4))


if __name__ == '__main__':
    main()
