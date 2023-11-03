import logging

import typer
from rich.logging import RichHandler

from bomsquad.vulndb.cli.admin import admin_app
from bomsquad.vulndb.cli.cve import cve_app
from bomsquad.vulndb.cli.ingest import nvd_app
from bomsquad.vulndb.cli.ingest import osv_app
from bomsquad.vulndb.cli.purl import purl_app


app = typer.Typer()

app.add_typer(admin_app)
app.add_typer(osv_app)
app.add_typer(nvd_app)
app.add_typer(purl_app)
app.add_typer(cve_app)


@app.callback()
def app_main(verbose: bool = False) -> None:
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=log_level, format=format, datefmt="[%X]", handlers=[RichHandler(level=log_level)]
    )
