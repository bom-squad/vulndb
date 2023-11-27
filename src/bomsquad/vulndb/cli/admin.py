from typer import Option
from typer import Typer

from bomsquad.vulndb.db.manager import instance as database_manager

admin_app = Typer(name="admin")


@admin_app.command(name="create")
def _create() -> None:
    """
    Create schema, tables, indices, and user for active configuration.
    """
    database_manager.create()
    database_manager.create_tables()


@admin_app.command(name="drop")
def _drop(show_only: bool = Option(default=False)) -> None:
    """
    Drop database from active configuration.
    """
    database_manager.drop(show_only)
