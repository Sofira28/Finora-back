"""Registro de todos los modelos en Base.metadata (Alembic y pruebas)."""

import importlib

# Un módulo por feature con tablas; agregar aquí cada uno nuevo.
_MODEL_MODULES = ("finora.auth.models", "finora.accounts.models")


def load_all_models() -> None:
    for module in _MODEL_MODULES:
        importlib.import_module(module)
