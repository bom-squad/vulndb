from typer import Option
from typer import Typer

from bomsquad.vulndb.db.manager import instance as database_manager

admin_app = Typer(name="admin")


@admin_app.command(name="create_all")
def _create_all() -> None:
    """
    Create schema, tables, indices, and user for active configuration.
    """
    database_manager.create()
    database_manager.create_tables()
    database_manager.create_user()


@admin_app.command(name="create_db")
def _create_db(show_only: bool = Option(default=False)) -> None:
    """
    Create database for active configuration.
    """
    database_manager.create(show_only)


@admin_app.command(name="create_tables")
def _create_tables(show_only: bool = Option(default=False)) -> None:
    """
    Create tables and indiciates for active configuration.
    """
    database_manager.create_tables(show_only)


@admin_app.command(name="create_user")
def _create_user(show_only: bool = Option(default=False)) -> None:
    """
    Create user for active configuration.
    """
    database_manager.create_user(show_only)


@admin_app.command(name="drop_all")
def _drop_all(show_only: bool = Option(default=False)) -> None:
    """
    Drop database from active configuration.
    """
    database_manager.drop(show_only)
