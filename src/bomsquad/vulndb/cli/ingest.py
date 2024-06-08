from typing import Optional

import typer

from bomsquad.vulndb.db.ingest import Ingest

nvd_app = typer.Typer(name="nvd")
osv_app = typer.Typer(name="osv")


@nvd_app.command(name="ingest")
def _nvd_ingest(
    scope: Optional[str] = typer.Option(default=None, help="Ingest only cve or cpe "),
    update: bool = typer.Option(default=False, help="Acquire records newer than current data"),
) -> None:
    if scope == "cve" or scope is None:
        Ingest.cve(update=update)
    if scope == "cpe" or scope is None:
        Ingest.cpe(update=update)


@osv_app.command(name="ingest")
def _osv_ingest(
    ecosystem: Optional[str] = typer.Option(default=None, help="Ingest only a single ecosystem"),
    offset: int = typer.Option(default=0, help="Offset into available entries to begin wtih"),
    limit: Optional[int] = typer.Option(default=None, help="Limit the number of entries to ingest"),
) -> None:
    if ecosystem:
        Ingest.osv(ecosystem, offset, limit)
    else:
        if offset != 0 or limit:
            raise ValueError("Offset and limit are only valid with a specific ecosystem")
        Ingest.all_osv()
