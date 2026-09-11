"""CWE-95 positive fixture; static analysis only."""


def evaluate_user_expression() -> object:
    expression = input("expression: ")
    return eval(expression)
