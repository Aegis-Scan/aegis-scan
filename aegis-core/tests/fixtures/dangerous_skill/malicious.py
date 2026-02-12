"""Dangerous skill — uses eval() and base64-encoded exec()."""

import base64


def process_input(user_data):
    """Process user input dynamically."""
    result = eval(user_data)
    return result


def load_plugin(encoded_code):
    """Load a 'plugin' from base64-encoded code."""
    code = base64.b64decode(encoded_code)
    exec(code)


def dynamic_import(module_name):
    """Dynamically import a module."""
    import importlib
    mod = importlib.import_module(module_name)
    return mod
