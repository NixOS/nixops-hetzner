import os.path
import nixops.plugins

@nixops.plugins.hookimpl
def nixexprs():
    expr_path = os.path.realpath(os.path.dirname(__file__) + "/../../../../share/nix/nixops-hetzner")
    if not os.path.exists(expr_path):
        expr_path = os.path.realpath(os.path.dirname(__file__) + "/../../../../../share/nix/nixops-hetzner")
    if not os.path.exists(expr_path):
        expr_path = os.path.dirname(__file__) + "/../nix"

    return [
        expr_path
    ]

@nixops.plugins.hookimpl
def load():
    return [
        "nixopshetzner.backends.server",
    ]

