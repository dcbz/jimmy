"""jimmy — AI harness for restricted-shell capability research.

See README.md for architecture. Safety contract: every Target must be
explicitly disposable; the harness never points at production machines and
never lets the model redefine the policy that judges success.
"""

__version__ = "0.1.0"
