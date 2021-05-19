import os.path
import nixops.plugins
from nixops.plugins import Plugin


class NixopsHetznerPlugin(Plugin):
    @staticmethod
    def nixexprs():
        return [os.path.dirname(os.path.abspath(__file__)) + "/nix"]

    @staticmethod
    def load():
        return [
            "nixops_hetzner.resources",
            "nixops_hetzner.backends.server",
        ]


@nixops.plugins.hookimpl
def plugin():
    return NixopsHetznerPlugin()
